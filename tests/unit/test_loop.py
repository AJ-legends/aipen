"""S4 tests: nuclei parser, analyst, verifier, loop closure, gateway, invariants."""
import asyncio
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import respx

from app.ai.analyst import EvidenceView, SignalView, analyze_evidence
from app.ai.gateway import AIGateway, AIRole, BudgetContext
from app.ai.loop import LoopService
from app.ai.verifier import verify_hypothesis
from app.core.db import connection, initialise_database
from app.core.schemas import VerificationVote
from app.signals.parsers import parse_nuclei_jsonl

BASE_URL = "https://app.example.test/search"
SCOPE = {
    "allowed_domains": ["*.example.test"],
    "allowed_ips": [],
    "allowed_ports": [443],
    "allowed_path_prefixes": ["/"],
    "excluded_paths": [],
    "rate_limit_per_second": 20,
    "allowed_test_types": ["recon", "discovery", "signals", "sqli", "xss"],
    "forbidden_actions": ["state_change"],
}


def _seed(db_path: Path) -> tuple[UUID, UUID]:
    target_id = uuid4()
    run_id = uuid4()
    now = datetime.now(UTC).isoformat()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (str(target_id), "t", json.dumps([BASE_URL]), json.dumps(SCOPE), 1, 0.50, now),
        )
        db.execute("INSERT INTO runs (id, target_id, state, created_at, config) VALUES (?, ?, 'verify', ?, ?)", (str(run_id), str(target_id), now, json.dumps({})))
    return target_id, run_id


def _seed_probe_evidence(db_path: Path, run_id: UUID, target_id: UUID, *, markers: tuple[str, ...] = ("you have an error in your sql syntax",), timing: bool = False) -> UUID:
    action_id = uuid4()
    evidence_id = uuid4()
    now = datetime.now(UTC).isoformat()
    analysis = {
        "module": "sqli", "kind": "error-based", "param": "q", "payload": "'",
        "baseline": {"url": BASE_URL, "status": 200, "length": 100},
        "mutated": {"url": BASE_URL, "status": 200, "length": 400},
        "diff": {"status_changed": False, "length_delta": 300, "markers": list(markers), "timing_ms": 5.0, "timing_anomaly": timing},
        "signals": ["markers:x"] if markers else [],
    }
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(action_id), str(run_id), str(target_id), "sqli", json.dumps({"url": BASE_URL, "param": "q", "payload": "'", "kind": "error-based"}), "low", "allow", "auto", now),
        )
        db.execute(
            "INSERT INTO evidence (id, test_action_id, kind, artifact_ref, analysis, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (str(evidence_id), str(action_id), "diff", None, json.dumps(analysis), now),
        )
    return evidence_id


def _view(**overrides: object) -> EvidenceView:
    values: dict[str, object] = {"id": uuid4(), "kind": "diff", "module": "sqli", "param": "q", "endpoint_url": BASE_URL}
    values.update(overrides)
    return EvidenceView(**values)  # type: ignore[arg-type]


def test_nuclei_parser_fixture() -> None:
    signals = parse_nuclei_jsonl((Path(__file__).parent.parent / "fixtures" / "nuclei-sample.jsonl").read_bytes())
    assert len(signals) == 3
    assert signals[0].template_id == "http-missing-security-headers"
    assert signals[1].severity == "high"
    assert signals[2].template_id == "xss-reflected"


def test_analyst_groups_and_skips_encoded() -> None:
    evidence = (
        _view(markers=("you have an error in your sql syntax",)),
        _view(kind="analysis", module="xss", xss_context="raw"),
        _view(kind="analysis", module="xss", xss_context="encoded"),
    )
    drafts = analyze_evidence(evidence, ())
    by_class = {draft.vuln_class: draft for draft in drafts}
    assert set(by_class) == {"sqli", "xss"}
    assert by_class["sqli"].confidence == 0.7
    assert len(by_class["xss"].evidence_ids) == 1
    signal_drafts = analyze_evidence((), (SignalView(endpoint_url=BASE_URL, template_id="sqli-error-based", name="SQLi", severity="high"),))
    assert signal_drafts[0].confidence == 0.4 and signal_drafts[0].evidence_ids == ()


def test_verifier_matrix() -> None:
    assert verify_hypothesis("sqli", (_view(markers=("x",)),)).vote is VerificationVote.CONFIRM
    assert verify_hypothesis("sqli", (_view(markers=("x",)),), ("q",)).vote is VerificationVote.CONFIRM
    assert verify_hypothesis("sqli", (_view(timing_anomaly=True),)).vote is VerificationVote.UNCERTAIN
    assert verify_hypothesis("sqli", (_view(),)).vote is VerificationVote.REJECT
    assert verify_hypothesis("sqli", ()).vote is VerificationVote.REJECT
    assert verify_hypothesis("xss", (_view(module="xss", xss_context="attribute"),)).vote is VerificationVote.CONFIRM
    assert verify_hypothesis("xss", (_view(module="xss", xss_context="encoded"),)).vote is VerificationVote.REJECT
    assert verify_hypothesis("xxe", (_view(),)).vote is VerificationVote.REJECT


def test_loop_confirms_finding(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    _seed_probe_evidence(db_path, run_id, target_id)
    loop = LoopService(db_path, tmp_path / "artifacts")
    summary = asyncio.run(loop.analyze_run(run_id))
    assert summary["hypotheses_new"] == 1 and summary["verified"] == 1 and summary["findings"]
    with connection(db_path) as db:
        finding = db.execute("SELECT severity, hypothesis_id FROM findings").fetchone()
        hypothesis = db.execute("SELECT status FROM hypotheses").fetchone()
        votes = db.execute("SELECT vote FROM verifications").fetchall()
    assert finding["severity"] == "high" and hypothesis["status"] == "verified"
    assert [row["vote"] for row in votes] == ["confirm"]
    # Second pass is idempotent: no duplicates.
    again = asyncio.run(loop.analyze_run(run_id))
    assert again["hypotheses_new"] == 0 and again["verified"] == 0


def test_loop_stale_after_followups(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    _seed_probe_evidence(db_path, run_id, target_id, markers=(), timing=True)

    class QuietTesting:
        async def run_plan(self, run_id: UUID, plans: object, max_probes: int = 20) -> dict[str, object]:
            return {"probed": 0, "blocked": 0, "signals": 0, "sqlmap_findings": [], "warnings": []}

    loop = LoopService(db_path, tmp_path / "artifacts", testing=QuietTesting())  # type: ignore[arg-type]
    summary = asyncio.run(loop.analyze_run(run_id))
    assert summary["stale"] == 1 and summary["findings"] == []
    with connection(db_path) as db:
        row = db.execute("SELECT status, followups FROM hypotheses").fetchone()
    assert row["status"] == "stale" and row["followups"] == 2


def test_finding_trigger_requires_confirm(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    now = datetime.now(UTC).isoformat()
    hypothesis_id, verification_id = uuid4(), uuid4()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO hypotheses (id, run_id, target_id, endpoint_url, vuln_class, rationale, confidence, author, prompt_version, status, evidence_ids, followups, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 0, ?)",
            (str(hypothesis_id), str(run_id), str(target_id), BASE_URL, "sqli", "r", 0.5, "deterministic", "analyst.v1", json.dumps([]), now),
        )
        db.execute(
            "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(verification_id), str(hypothesis_id), "deterministic", "reject", "no", json.dumps([]), now),
        )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO findings (id, run_id, target_id, hypothesis_id, verification_id, title, severity, endpoint_url, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid4()), str(run_id), str(target_id), str(hypothesis_id), str(verification_id), "t", "high", BASE_URL, "d", now),
            )


def _gateway(db_path: Path) -> AIGateway:
    from app.ai.config import AIConfig

    return AIGateway(db_path, AIConfig(api_key="test-key", base_url="https://gateway.test/v1"))


def _completion(content: str) -> dict[str, object]:
    return {"model": "deepseek-chat", "choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


def test_gateway_happy_path_and_ledger(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    gateway = _gateway(db_path)
    budget = BudgetContext(run_budget_usd=0.50, spent_usd=0.0)
    with respx.mock(base_url="https://gateway.test/v1") as mock:
        mock.post("/chat/completions").mock(return_value=httpx.Response(200, json=_completion('{"vote":"CONFIRM","reason":"r","evidence_ids":[]}')))
        result = gateway.generate(AIRole.VERIFIER, "p", {"required": ["vote", "reason", "evidence_ids"]}, budget)
    assert result["output"]["vote"] == "CONFIRM" and result["cost_usd"] >= 0
    with connection(db_path) as db:
        row = db.execute("SELECT role, model, usd FROM cost_ledger").fetchone()
    assert row["role"] == "verifier" and row["usd"] >= 0


def test_gateway_retry_and_routing() -> None:
    from app.ai.config import AIConfig
    from app.ai.router import provider_of, resolve_model

    assert provider_of("deepseek-chat") == "deepseek"
    config = AIConfig(api_key="k", verify_models=("deepseek-chat", "claude-3-5-sonnet-latest"))
    assert resolve_model(AIRole.VERIFIER, config, author_model="deepseek-chat") == "claude-3-5-sonnet-latest"
    assert resolve_model(AIRole.VERIFIER, config, author_model="gpt-4o-mini") == "deepseek-chat"
    assert resolve_model(AIRole.ANALYST, config) == config.volume_model


def test_gateway_guards(tmp_path: Path) -> None:
    from app.ai import providers as provider_adapter
    from app.ai.config import AIConfig

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    assert not AIConfig().configured
    with pytest.raises(provider_adapter.ProviderError):
        AIGateway(db_path, AIConfig()).generate(AIRole.ANALYST, "p", {"required": ["a"]}, BudgetContext(0.5, 0.0))
    with pytest.raises(RuntimeError):
        _gateway(db_path).generate(AIRole.ANALYST, "p", {"required": ["a"]}, BudgetContext(0.5, 0.5))


def test_gateway_backoff_retry_then_success(tmp_path: Path) -> None:
    from app.ai import providers as provider_adapter

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    gateway = _gateway(db_path)
    budget = BudgetContext(run_budget_usd=0.50, spent_usd=0.0)
    with respx.mock(base_url="https://gateway.test/v1") as mock:
        route = mock.post("/chat/completions").mock(
            side_effect=[
                httpx.Response(429, json={"error": "busy"}),
                httpx.Response(200, json=_completion('{"vote":"CONFIRM","reason":"r","evidence_ids":[]}')),
            ]
        )
        result = gateway.generate(
            AIRole.VERIFIER, "p", {"required": ["vote", "reason", "evidence_ids"]}, budget, transport=None
        )
    assert result["output"]["vote"] == "CONFIRM"
    assert route.call_count == 2
    assert provider_adapter.RETRYABLE_STATUS >= {429}


def test_gateway_falls_back_and_audits(tmp_path: Path) -> None:
    from app.ai.config import AIConfig

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    config = AIConfig(api_key="test-key", base_url="https://gateway.test/v1", volume_model="deepseek-chat", premium_model="claude-x", verify_models=("deepseek-chat",))
    gateway = AIGateway(db_path, config)
    budget = BudgetContext(run_budget_usd=0.50, spent_usd=0.0)
    with respx.mock(base_url="https://gateway.test/v1") as mock:
        route = mock.post("/chat/completions").mock(
            side_effect=[
                httpx.Response(500, json={"error": "down"}),
                httpx.Response(500, json={"error": "down"}),
                httpx.Response(200, json=_completion('{"vote":"REJECT","reason":"r","evidence_ids":[]}')),
            ]
        )
        result = gateway.generate(AIRole.ANALYST, "p", {"required": ["vote", "reason", "evidence_ids"]}, budget)
    assert result["output"]["vote"] == "REJECT"
    assert route.call_count == 3  # primary + backoff retry, then fallback model
    with connection(db_path) as db:
        audit = db.execute("SELECT detail FROM audit_log WHERE event = 'provider_fallback'").fetchone()
    assert audit is not None and "deepseek-chat" in audit["detail"]


def test_tls_verify_setting(monkeypatch: object) -> None:
    import ssl

    from app.ai.providers import tls_verify_setting

    monkeypatch.delenv("AIPEN_TLS_MAX", raising=False)  # type: ignore[attr-defined]
    assert tls_verify_setting() is True
    monkeypatch.setenv("AIPEN_TLS_MAX", "1.2")  # type: ignore[attr-defined]
    pinned = tls_verify_setting()
    assert isinstance(pinned, ssl.SSLContext) and pinned.maximum_version is ssl.TLSVersion.TLSv1_2
    monkeypatch.setenv("AIPEN_TLS_MAX", "bogus")  # type: ignore[attr-defined]
    assert tls_verify_setting() is True


def _ai_loop(db_path: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    from app.ai.loop import LoopService

    return LoopService(db_path, tmp_path / "artifacts", gateway=_gateway(db_path))


def _ai_completion(content: str) -> dict[str, object]:
    return {"model": "deepseek-chat", "choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 20, "completion_tokens": 10}}


def test_ai_analyst_and_verifier_drive_findings(tmp_path: Path) -> None:
    import asyncio

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    evidence_id = _seed_probe_evidence(db_path, run_id, target_id)
    analyst_body = json.dumps({"hypotheses": [{"endpoint_url": BASE_URL, "vuln_class": "xss", "rationale": "echo?", "confidence": 0.6, "evidence_ids": [str(evidence_id)]}]})
    verifier_body = json.dumps({"vote": "CONFIRM", "reason": "repro shown", "evidence_ids": [str(evidence_id)]})
    with respx.mock(base_url="https://gateway.test/v1") as mock:
        mock.post("/chat/completions").mock(
            side_effect=[
                httpx.Response(200, json=_ai_completion(analyst_body)),
                httpx.Response(200, json=_ai_completion(verifier_body)),
                httpx.Response(200, json=_ai_completion(verifier_body)),
            ]
        )
        summary = asyncio.run(_ai_loop(db_path, tmp_path).analyze_run(run_id, use_ai=True))  # type: ignore[arg-type]
    assert summary["verified"] == 2 and len(summary["findings"]) == 2
    with connection(db_path) as db:
        authors = {row["author"] for row in db.execute("SELECT author FROM hypotheses").fetchall()}
        voters = {row["voter"] for row in db.execute("SELECT voter FROM verifications").fetchall()}
        ledger = db.execute("SELECT COUNT(*) AS n FROM cost_ledger").fetchone()
    assert "deepseek-chat" in authors and "deepseek-chat" in voters and ledger["n"] >= 3
    assert "ai_notes" in summary


def test_ai_invalid_draft_dropped_and_budget_gates(tmp_path: Path) -> None:
    import asyncio

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    _seed_probe_evidence(db_path, run_id, target_id)
    bad_body = json.dumps({"hypotheses": [{"endpoint_url": "https://evil.test/x", "vuln_class": "rce", "rationale": "trust me", "confidence": 0.99, "evidence_ids": [str(uuid4())]}]})
    with respx.mock(base_url="https://gateway.test/v1") as mock:
        mock.post("/chat/completions").mock(return_value=httpx.Response(200, json=_ai_completion(bad_body)))
        summary = asyncio.run(_ai_loop(db_path, tmp_path).analyze_run(run_id, use_ai=True))  # type: ignore[arg-type]
    # Bogus draft dropped; deterministic baseline still confirms the real one.
    assert summary["verified"] == 1 and "dropped" in str(summary.get("ai_notes"))
    # use_ai=False spends nothing and adds no ai_notes.
    plain = asyncio.run(_ai_loop(db_path, tmp_path).analyze_run(run_id))
    assert "ai_notes" not in plain
    with connection(db_path) as db:
        ledger = db.execute("SELECT COUNT(*) AS n FROM cost_ledger").fetchone()
    assert ledger["n"] >= 1  # only the use_ai pass spent

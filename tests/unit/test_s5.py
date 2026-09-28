"""S5 tests: risk classifier, IDOR/SSRF/API modules, approvals HITL, OOB, migration."""
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.api.routes import build_router
from app.approvals.service import ApprovalService
from app.core.db import connection, ensure_column, initialise_database
from app.core.schemas import RiskTier
from app.testing.adapters.sqlmap import SqlmapResult
from app.testing.modules.api import VERBOSE_ERROR_MARKERS, api_probes
from app.testing.modules.idor import idor_probes, is_identifier_param, sequential_variants
from app.testing.modules.ssrf import is_urlish_param, ssrf_probes
from app.testing.risk import classify
from app.testing.service import TestingService

BASE_URL = "https://app.example.test/users?id=7"
SCOPE = {
    "allowed_domains": ["*.example.test"],
    "allowed_ips": [],
    "allowed_ports": [443],
    "allowed_path_prefixes": ["/"],
    "excluded_paths": [],
    "rate_limit_per_second": 20,
    "allowed_test_types": ["recon", "discovery", "signals", "sqli", "xss", "idor", "ssrf", "api"],
    "forbidden_actions": ["state_change"],
}
SESSIONS = [{"name": "A", "headers": {"Cookie": "session=a"}}, {"name": "B", "headers": {"Cookie": "session=b"}}]


def _seed(db_path: Path, sessions: object = None) -> tuple[UUID, UUID]:
    target_id = uuid4()
    run_id = uuid4()
    now = datetime.now(UTC).isoformat()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived, sessions) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (str(target_id), "t", json.dumps([BASE_URL]), json.dumps(SCOPE), 1, 0.50, now, json.dumps(sessions or [])),
        )
        db.execute("INSERT INTO runs (id, target_id, state, created_at, config) VALUES (?, ?, 'signals', ?, ?)", (str(run_id), str(target_id), now, json.dumps({})))
        db.execute(
            "INSERT INTO endpoints (id, target_id, url, method, params, form_fields, is_api, source, first_seen) VALUES (?, ?, ?, 'GET', ?, ?, 0, 'katana', ?)",
            (str(uuid4()), str(target_id), "https://app.example.test/users", json.dumps(["id"]), json.dumps([]), now),
        )
    return target_id, run_id


def test_risk_matrix() -> None:
    assert classify("sqli", "error-based") is RiskTier.LOW
    assert classify("idor", "sequential") is RiskTier.LOW
    assert classify("idor", "cross-account") is RiskTier.MEDIUM
    assert classify("api", "mass-assignment") is RiskTier.MEDIUM
    assert classify("sqli", "error-based", method="POST") is RiskTier.HIGH
    assert classify("rce", "boom") is RiskTier.HIGH


def test_idor_helpers() -> None:
    assert is_identifier_param("user_id") and is_identifier_param("id")
    assert not is_identifier_param("search")
    assert sequential_variants("7")[:2] == ["8", "6"]
    assert len(sequential_variants("123e4567-e89b-12d3-a456-426614174000")) == 2
    assert [probe.kind for probe in idor_probes("id", "7")] == ["sequential"] * 4
    cross = idor_probes("id", "7", sessions=("A", "B"))
    assert any(probe.kind == "cross-account" and probe.risk_tier == "medium" for probe in cross)
    assert any(probe.kind == "unauthenticated" for probe in cross)


def test_ssrf_and_api_helpers(tmp_path: Path) -> None:
    assert is_urlish_param("callback") and not is_urlish_param("search")
    probes = ssrf_probes("callback", "http://127.0.0.1:8000/api/oob", token="abc123")
    assert probes[0].payload == "http://127.0.0.1:8000/api/oob/abc123"
    assert probes[0].risk_tier == "low"
    assert api_probes("https://app.example.test/page", "q") == []
    api = api_probes("https://app.example.test/api/items", "id", sessions=("A",))
    kinds = {probe.kind for probe in api}
    assert {"verbose-errors", "bola-query", "unauthenticated", "mass-assignment"} <= kinds
    assert VERBOSE_ERROR_MARKERS


def test_approvals_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    service = ApprovalService(db_path)
    approval_id = service.request(uuid4(), {"url": BASE_URL}, RiskTier.MEDIUM, "why", "effect", run_id=uuid4())
    assert len(service.pending()) == 1
    assert service.decide(approval_id, True).value == "approved"
    assert service.pending() == []
    with pytest.raises(ValueError):
        service.decide(approval_id, True)
    with pytest.raises(LookupError):
        service.decide(uuid4(), True)


def test_migration_adds_sessions(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "old.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as database:
        database.execute("CREATE TABLE targets (id TEXT PRIMARY KEY, name TEXT NOT NULL)")
    assert ensure_column(db_path, "targets", "sessions", "TEXT NOT NULL DEFAULT '[]'") is True
    assert ensure_column(db_path, "targets", "sessions", "TEXT NOT NULL DEFAULT '[]'") is False
    initialise_database(tmp_path / "fresh.db")  # fresh schema already carries the column


def test_hitl_pause_and_continue(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed(db_path, SESSIONS)
    service = TestingService(db_path, tmp_path / "artifacts", sqlmap_runner=lambda cmd: SqlmapResult(findings=(), raw=b""))
    plans, warnings = service.plans_for_run(run_id, ("idor",))  # type: ignore[arg-type]
    assert warnings == []
    assert any(probe.kind == "cross-account" for plan in plans for probe in plan.probes)
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://app.example.test/users").mock(return_value=httpx.Response(200, text="same"))
        summary = asyncio.run(service.run_plan(run_id, plans, max_probes=50))  # type: ignore[arg-type]
    assert summary["pending_approvals"] >= 1 and summary["probed"] >= 1
    with connection(db_path) as db:
        pending = db.execute("SELECT id FROM approvals WHERE state = 'pending'").fetchall()
    assert pending
    service.approvals.decide(UUID(pending[0]["id"]), True)
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://app.example.test/users").mock(return_value=httpx.Response(200, text="user 8"))
        result = asyncio.run(service.execute_approved(run_id))  # type: ignore[arg-type]
    assert result["probed"] >= 1
    with connection(db_path) as db:
        executed = db.execute("SELECT id FROM test_actions WHERE approval_state = 'executed'").fetchall()
    assert executed


def test_oob_endpoint_and_422(tmp_path: Path) -> None:
    from fastapi import FastAPI

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    app = FastAPI()
    app.include_router(build_router(db_path))
    client = TestClient(app)
    resp = client.post("/api/oob/abc123")
    assert resp.status_code == 202
    assert client.post("/api/oob/bad token").status_code == 422
    target = client.post("/api/targets", json={"name": "t", "base_urls": [BASE_URL], "scope": SCOPE, "sessions": SESSIONS})
    assert target.status_code == 201, target.text


def test_loop_idor_ssrf_branches(tmp_path: Path) -> None:
    from app.ai.analyst import EvidenceView
    from app.ai.loop import LoopService
    from app.ai.verifier import verify_hypothesis

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    now = datetime.now(UTC).isoformat()
    diff_analysis = {
        "signals": ["status:200->200"],
        "baseline": {"url": BASE_URL, "status": 200, "length": 100},
        "mutated": {"url": BASE_URL, "status": 200, "length": 400},
        "diff": {"status_changed": True, "length_delta": 300, "markers": [], "timing_ms": 1.0, "timing_anomaly": False},
    }
    with connection(db_path) as db:
        action_id = uuid4()
        db.execute(
            "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(action_id), str(run_id), str(target_id), "idor", json.dumps({"url": BASE_URL, "param": "id", "payload": "8", "kind": "sequential"}), "low", "allow", "auto", now),
        )
        db.execute("INSERT INTO evidence (id, test_action_id, kind, analysis, created_at) VALUES (?, ?, 'diff', ?, ?)", (str(uuid4()), str(action_id), json.dumps(diff_analysis), now))
        db.execute("INSERT INTO oob_callbacks (id, token, received_at) VALUES (?, ?, ?)", (str(uuid4()), "tok-1", now))
    loop = LoopService(db_path, tmp_path / "artifacts")
    summary = asyncio.run(loop.analyze_run(run_id))  # type: ignore[arg-type]
    assert summary["verified"] == 1 and len(summary["findings"]) == 1
    view = EvidenceView(id=uuid4(), kind="diff", module="ssrf", param="callback", endpoint_url=BASE_URL, ssrf_token="tok-1")
    assert verify_hypothesis("ssrf", (view,), oob_hits=("tok-1",)).vote.value == "confirm"
    assert verify_hypothesis("ssrf", (view,), oob_hits=()).vote.value == "uncertain"


def test_execute_approved_restores_context_and_rechecks(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed(db_path, SESSIONS)
    service = TestingService(db_path, tmp_path / "artifacts", sqlmap_runner=lambda cmd: SqlmapResult(findings=(), raw=b""))
    plans, _ = service.plans_for_run(run_id, ("idor",))  # type: ignore[arg-type]
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://app.example.test/users").mock(return_value=httpx.Response(200, text="same"))
        asyncio.run(service.run_plan(run_id, plans, max_probes=50))  # type: ignore[arg-type]
    with connection(db_path) as db:
        pending = db.execute("SELECT id FROM approvals WHERE state = 'pending'").fetchall()
        cross_action = db.execute("SELECT payload, risk_tier FROM test_actions WHERE type = 'idor' AND payload LIKE '%cross-account%'").fetchone()
    assert pending and cross_action is not None
    stored = json.loads(cross_action["payload"])
    assert stored["session"] == "B" and cross_action["risk_tier"] == "medium"
    service.approvals.decide(UUID(pending[0]["id"]), True)
    # Scope narrows before execution: the approved probe must NOT run.
    with connection(db_path) as db:
        db.execute("UPDATE targets SET scope_config = ? WHERE id = (SELECT target_id FROM runs WHERE id = ?)",
                   (json.dumps({**SCOPE, "allowed_test_types": ["recon"]}), str(run_id)))
    with respx.mock(assert_all_called=False):
        result = asyncio.run(service.execute_approved(run_id))  # type: ignore[arg-type]
    assert result["probed"] == 0 and result["skipped"] >= 1
    with connection(db_path) as db:
        still_pending = db.execute("SELECT COUNT(*) AS n FROM test_actions WHERE approval_state = 'pending'").fetchone()
    assert still_pending["n"] >= 1


def test_finding_trigger_rejects_mismatch_and_empty(tmp_path: Path) -> None:
    import sqlite3

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed(db_path)
    now = datetime.now(UTC).isoformat()
    hyp_a, hyp_b, verification_id, evidence_id = uuid4(), uuid4(), uuid4(), uuid4()
    with connection(db_path) as db:
        for hyp in (hyp_a, hyp_b):
            db.execute(
                "INSERT INTO hypotheses (id, run_id, target_id, endpoint_url, vuln_class, rationale, confidence, author, prompt_version, status, evidence_ids, followups, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 0, ?)",
                (str(hyp), str(run_id), str(target_id), BASE_URL, "sqli", "r", 0.5, "deterministic", "analyst.v1", json.dumps([str(evidence_id)]), now),
            )
        db.execute(
            "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid4()), str(run_id), str(target_id), "sqli", json.dumps({"url": BASE_URL}), "low", "allow", "auto", now),
        )
        action = db.execute("SELECT id FROM test_actions").fetchone()
        db.execute("INSERT INTO evidence (id, test_action_id, kind, analysis, created_at) VALUES (?, ?, 'diff', ?, ?)", (str(evidence_id), action["id"], json.dumps({}), now))
        # CONFIRM vote for hyp_a, but finding filed under hyp_b -> must abort.
        db.execute(
            "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(verification_id), str(hyp_a), "deterministic", "confirm", "r", json.dumps([str(evidence_id)]), now),
        )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO findings (id, run_id, target_id, hypothesis_id, verification_id, title, severity, endpoint_url, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid4()), str(run_id), str(target_id), str(hyp_b), str(verification_id), "t", "high", BASE_URL, "d", now),
            )
        # CONFIRM with zero cited evidence -> must abort too.
        empty_vote = uuid4()
        db.execute(
            "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(empty_vote), str(hyp_a), "deterministic", "confirm", "r", json.dumps([]), now),
        )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO findings (id, run_id, target_id, hypothesis_id, verification_id, title, severity, endpoint_url, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid4()), str(run_id), str(target_id), str(hyp_a), str(empty_vote), "t", "high", BASE_URL, "d", now),
            )

"""S6 tests: report engine (MD/HTML/JSON), metrics, and API endpoints."""
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes import build_router
from app.core.db import connection, initialise_database
from app.reports.metrics import compute_metrics
from app.reports.renderer import build_curl_commands, build_report, render_html, render_markdown

BASE_URL = "https://app.example.test/search?q=1"


def _seed_report_db(db_path: Path):  # type: ignore[no-untyped-def]
    target_id = uuid4()
    run_id = uuid4()
    now = datetime.now(UTC).isoformat()
    scope = {
        "allowed_domains": ["*.example.test"],
        "allowed_ips": [],
        "allowed_ports": [443],
        "allowed_path_prefixes": ["/"],
        "excluded_paths": [],
        "rate_limit_per_second": 20,
        "allowed_test_types": ["recon", "sqli", "xss"],
        "forbidden_actions": ["state_change"],
    }
    hyp_id = uuid4()
    rej_id = uuid4()
    ver_id = uuid4()
    rej_ver = uuid4()
    ev_id = uuid4()
    action_id = uuid4()
    finding_id = uuid4()
    analysis = {
        "baseline": {"url": BASE_URL, "status": 200, "length": 100},
        "mutated": {"url": BASE_URL + "'", "status": 200, "length": 400},
        "diff": {"status_changed": False, "length_delta": 300, "markers": ["sql syntax"], "timing_ms": 5.0, "timing_anomaly": False},
        "signals": ["markers:sql syntax"],
    }
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived, sessions) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (str(target_id), "demo", json.dumps([BASE_URL]), json.dumps(scope), 1, 0.50, now, json.dumps([])),
        )
        db.execute("INSERT INTO runs (id, target_id, state, created_at, config) VALUES (?, ?, 'reporting', ?, ?)", (str(run_id), str(target_id), now, json.dumps({})))
        db.execute(
            "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(action_id), str(run_id), str(target_id), "sqli", json.dumps({"url": BASE_URL, "param": "q", "payload": "'", "kind": "error-based"}), "low", "allow", "auto", now),
        )
        db.execute("INSERT INTO evidence (id, test_action_id, kind, analysis, created_at) VALUES (?, ?, 'diff', ?, ?)", (str(ev_id), str(action_id), json.dumps(analysis), now))
        for hid, status in ((hyp_id, "verified"), (rej_id, "rejected")):
            db.execute(
                "INSERT INTO hypotheses (id, run_id, target_id, endpoint_url, vuln_class, rationale, confidence, author, prompt_version, status, evidence_ids, followups, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (str(hid), str(run_id), str(target_id), BASE_URL, "sqli", "rationale", 0.7, "deterministic", "analyst.v1", status, json.dumps([str(ev_id)]), now),
            )
        db.execute(
            "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(ver_id), str(hyp_id), "deterministic", "confirm", "markers reproduced", json.dumps([str(ev_id)]), now),
        )
        db.execute(
            "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(rej_ver), str(rej_id), "deterministic", "reject", "no markers", json.dumps([str(ev_id)]), now),
        )
        db.execute(
            "INSERT INTO findings (id, run_id, target_id, hypothesis_id, verification_id, title, severity, endpoint_url, description, repro, impact, remediation, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(finding_id), str(run_id), str(target_id), str(hyp_id), str(ver_id), "SQLI on " + BASE_URL, "high", BASE_URL, "desc", json.dumps({"endpoint": BASE_URL, "probes": ["q='"]}), "impact", "remediation", 0.8, now),
        )
        db.execute("INSERT INTO cost_ledger (ts, run_id, role, provider, model, input_tokens, output_tokens, usd) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (now, str(run_id), "analyst", "test", "m", 10, 5, 0.02))
    return target_id, run_id


def test_build_curl_prefers_mutated_url() -> None:
    evidence = [{"mutated": {"url": BASE_URL + "'"}, "param": "q"}]
    commands = build_curl_commands(BASE_URL, ["q='"], evidence)  # type: ignore[arg-type]
    assert commands and commands[0] == f'curl -s -X GET "{BASE_URL}\'"'
    fallback = build_curl_commands("https://h.test/page", [], [])
    assert fallback == ['curl -s -X GET "https://h.test/page"']


def test_report_ordering_and_repro(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed_report_db(db_path)
    data = build_report(target_id, db_path, run_id)
    assert data["summary"]["findings_total"] == 1
    finding = data["findings"][0]  # type: ignore[index]
    assert finding["severity"] == "high"
    assert finding["curl_commands"]
    assert "curl -s" in finding["curl_commands"][0]
    markdown = render_markdown(data)
    assert "# AIPEN findings report" in markdown
    assert "## Executive summary" in markdown
    assert "### Reproduction" in markdown
    assert "## Hypotheses ledger" in markdown
    assert "`confirm` by `deterministic`" in markdown
    page = render_html(data)
    assert "<html" in page and "SQLI on" in page


def test_report_empty_state(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = uuid4()
    now = datetime.now(UTC).isoformat()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived, sessions) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (str(target_id), "empty", json.dumps([BASE_URL]), json.dumps({"allowed_domains": ["x"]}), 1, 0.50, now, json.dumps([])),
        )
    data = build_report(target_id, db_path)
    assert data["summary"]["findings_total"] == 0
    assert "No verified findings" in render_markdown(data)


def test_metrics_values(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed_report_db(db_path)
    metrics = compute_metrics(db_path, run_id=run_id, planted_total=4)
    assert metrics["hypotheses_total"] == 2
    assert metrics["verified_findings"] == 1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["precision_proxy"] == 0.5
    assert metrics["recall"] == 0.25
    assert metrics["cost_per_finding"] == 0.02
    assert metrics["loop_efficiency"] == 1.0
    assert metrics["safety_out_of_scope_executions"] == 0
    assert metrics["time_to_first_finding_s"] is not None


def test_report_and_metrics_endpoints(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed_report_db(db_path)
    app = FastAPI()
    app.include_router(build_router(db_path))
    client = TestClient(app)
    payload = client.get(f"/api/targets/{target_id}/report", params={"run_id": str(run_id), "format": "json"})
    assert payload.status_code == 200, payload.text
    assert payload.json()["summary"]["findings_total"] == 1
    markdown = client.get(f"/api/targets/{target_id}/report", params={"run_id": str(run_id), "format": "md"})
    assert markdown.status_code == 200 and "# AIPEN findings report" in markdown.text
    page = client.get(f"/api/targets/{target_id}/report", params={"run_id": str(run_id), "format": "html"})
    assert page.status_code == 200 and "<html" in page.text
    metrics = client.get(f"/api/runs/{run_id}/metrics", params={"planted_total": 4})
    assert metrics.status_code == 200, metrics.text
    assert metrics.json()["verified_findings"] == 1
    assert client.get(f"/api/targets/{target_id}/metrics").status_code == 200
    assert client.get("/api/targets/00000000-0000-0000-0000-000000000000/report").status_code == 404

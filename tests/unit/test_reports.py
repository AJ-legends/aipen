"""S6 supplementary tests: CLI, run-scoped report/metrics routes, ground-truth recall.

Core renderer/metrics coverage lives in test_s6.py (prior spec, kept green);
this file covers the CLI surface, run-scoped routes, and detailed recall.
"""
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from _pytest.capture import CaptureFixture
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes import build_router
from app.core.db import connection, initialise_database
from app.reports.cli import main as cli_main
from app.reports.metrics import compute_metrics
from app.reports.renderer import build_report, render_markdown

BASE_URL = "https://app.example.test/search"
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


def _seed_run(db_path: Path) -> tuple[UUID, UUID]:
    from app.ai.loop import LoopService

    target_id = uuid4()
    run_id = uuid4()
    now = datetime.now(UTC).isoformat()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (str(target_id), "t", json.dumps([BASE_URL]), json.dumps(SCOPE), 1, 0.50, now),
        )
        db.execute("INSERT INTO runs (id, target_id, state, created_at, config) VALUES (?, ?, 'verify', ?, ?)", (str(run_id), str(target_id), now, json.dumps({})))
        action_id = uuid4()
        db.execute(
            "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(action_id), str(run_id), str(target_id), "sqli", json.dumps({"url": BASE_URL, "param": "q"}), "low", "allow", "auto", now),
        )
        db.execute(
            "INSERT INTO evidence (id, test_action_id, kind, analysis, created_at) VALUES (?, ?, 'diff', ?, ?)",
            (str(uuid4()), str(action_id), json.dumps({
                "baseline": {"url": BASE_URL, "status": 200, "length": 50},
                "mutated": {"url": BASE_URL, "status": 200, "length": 400},
                "diff": {"status_changed": False, "length_delta": 350, "markers": ["you have an error in your sql syntax"], "timing_ms": 2.0, "timing_anomaly": False},
                "signals": ["markers:x"]}), now),
        )
    artifacts = db_path.parent / "artifacts"
    artifacts.mkdir(exist_ok=True)
    asyncio.run(LoopService(db_path, artifacts).analyze_run(run_id))
    return target_id, run_id


def test_run_report_shapes(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id, run_id = _seed_run(db_path)
    data = build_report(target_id, db_path, run_id)
    assert data["summary"]["findings_total"] == 1
    assert "Hypotheses ledger" in render_markdown(data)


def test_metrics_ground_truth_detail(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed_run(db_path)
    ground_truth = [{"endpoint_contains": "/search", "vuln_class": "sqli"}, {"endpoint_contains": "/nope", "vuln_class": "xss"}]
    metrics = compute_metrics(db_path, run_id=run_id, ground_truth=ground_truth)
    assert metrics["recall"] == 0.5
    assert metrics["recall_detail"]["missed"] == [{"endpoint_contains": "/nope", "vuln_class": "xss"}]
    assert metrics["recall_detail"]["matched"] == 1
    with pytest.raises(ValueError):
        compute_metrics(db_path)


def test_cli_report_and_evaluate(tmp_path: Path, capsys: CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import config as config_module
    from app.reports import cli as cli_module

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed_run(db_path)
    # cli.py bound `settings` at import; repoint its reference for this test only.
    monkeypatch.setattr(cli_module, "settings", config_module.Settings(data_dir=tmp_path, database_name=db_path.name))
    assert cli_main(["report", str(run_id), "--format", "json"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["summary"]["findings_total"] == 1
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps([{"endpoint_contains": "/search", "vuln_class": "sqli"}]))
    assert cli_main(["evaluate", str(run_id), "--ground-truth", str(gt)]) == 0
    assert json.loads(capsys.readouterr().out)["recall"] == 1.0
    assert cli_main(["evaluate", str(run_id), "--planted-total", "4"]) == 0
    assert json.loads(capsys.readouterr().out)["recall"] == 0.25


def test_run_report_and_metrics_routes(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed_run(db_path)
    app = FastAPI()
    app.include_router(build_router(db_path))
    client = TestClient(app)
    assert client.get(f"/api/runs/{run_id}/report?format=markdown").status_code == 200
    html_resp = client.get(f"/api/runs/{run_id}/report?format=html")
    assert html_resp.status_code == 200 and "<html" in html_resp.text
    json_resp = client.get(f"/api/runs/{run_id}/report?format=json")
    assert json_resp.status_code == 200 and json_resp.json()["summary"]["findings_total"] == 1
    assert client.get(f"/api/runs/{run_id}/report?format=pdf").status_code == 422
    assert client.get(f"/api/runs/{uuid4()}/report").status_code == 404
    metrics_resp = client.get(f"/api/runs/{run_id}/metrics?planted_total=4")
    assert metrics_resp.status_code == 200 and metrics_resp.json()["recall"] == 0.25

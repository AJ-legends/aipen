"""Regression tests for early fixes: wordlists, probes, test_actions, backup."""
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.db import connection, initialise_database
from app.discovery.adapters import FfufAdapter, resolve_wordlist
from app.recon.models import HttpProbeRecord
from app.recon.service import ReconService

BASE_URL = "https://app.example.test/"
SCOPE = {
    "allowed_domains": ["*.example.test"],
    "allowed_ips": [],
    "allowed_ports": [443],
    "allowed_path_prefixes": ["/"],
    "excluded_paths": [],
    "rate_limit_per_second": 10,
    "allowed_test_types": ["recon", "discovery"],
    "forbidden_actions": ["state_change"],
}


def _seed_target(db_path: Path) -> object:
    target_id = uuid4()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (str(target_id), "t", json.dumps([BASE_URL]), json.dumps(SCOPE), 1, 0.50, datetime.now(UTC).isoformat()),
        )
    return target_id


def test_resolve_wordlist_allows_inside(tmp_path: Path) -> None:
    allowed = tmp_path / "wordlists"
    allowed.mkdir()
    wordlist = allowed / "common.txt"
    wordlist.write_text("admin\napi\n")
    resolved = resolve_wordlist(str(wordlist), (allowed,))
    assert resolved == wordlist.resolve()


def test_resolve_wordlist_rejects_traversal(tmp_path: Path) -> None:
    allowed = tmp_path / "wordlists"
    allowed.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    with pytest.raises(PermissionError):
        resolve_wordlist(str(outside), (allowed,))
    with pytest.raises(PermissionError):
        FfufAdapter().build_command(BASE_URL, str(outside), (allowed,))


def test_resolve_wordlist_rejects_missing(tmp_path: Path) -> None:
    allowed = tmp_path / "wordlists"
    allowed.mkdir()
    with pytest.raises(ValueError):
        resolve_wordlist(str(allowed / "nope.txt"), (allowed,))


def test_probes_persist_tech_and_feed_summary(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)
    recon = ReconService(db_path, tmp_path / "artifacts")
    recon._save_probes(  # type: ignore[attr-defined]  # private but stable for this test
        target_id,  # type: ignore[arg-type]
        (HttpProbeRecord(url=BASE_URL, status_code=200, title="T", webserver="nginx", technologies=("nginx", "FastAPI")),),
    )
    with connection(db_path) as db:
        row = db.execute("SELECT technologies FROM http_probes WHERE target_id = ?", (str(target_id),)).fetchone()
    assert row is not None and "FastAPI" in json.loads(row["technologies"])
    profile = recon.summarize(target_id)  # type: ignore[arg-type]
    assert "nginx" in profile.tech_stack


def test_test_actions_table_accepts_rows(tmp_path: Path) -> None:
    from app.orchestrator.service import RunService

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)
    runs = RunService(db_path, tmp_path / "artifacts")
    run = runs.create_run(target_id)  # type: ignore[arg-type]
    action_id = uuid4()
    now = datetime.now(UTC).isoformat()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(action_id), str(run.id), str(target_id), "sqli", json.dumps({}), "low", "allow", "n/a", now),
        )
        row = db.execute("SELECT policy_decision FROM test_actions WHERE id = ?", (str(action_id),)).fetchone()
    assert row["policy_decision"] == "allow"


def test_backup_is_valid_sqlite(tmp_path: Path) -> None:
    from app.orchestrator.service import RunService

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)
    runs = RunService(db_path, tmp_path / "artifacts")
    run = runs.create_run(target_id)  # type: ignore[arg-type]
    runs._backup_database(run.id)  # type: ignore[attr-defined]
    backup = tmp_path / "backups" / f"{run.id}.db"
    assert backup.exists()
    con = sqlite3.connect(backup)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()
    assert "runs" in tables and "targets" in tables

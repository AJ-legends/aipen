"""S3 tests: limiter, diffs, probes, modules, sqlmap adapter, policy gating."""
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx
import respx

from app.core.db import connection, initialise_database
from app.testing.adapters.sqlmap import (
    SqlmapFinding,
    SqlmapResult,
    build_command,
    execute,
    parse_output,
)
from app.testing.executor import RateLimiter, TestExecutor
from app.testing.models import Probe, ProbePlan
from app.testing.modules.sqli import SQLI_ERROR_MARKERS, sqli_probes
from app.testing.modules.xss import CANARY, classify_context, xss_probes
from app.testing.service import TestingService

BASE_URL = "https://app.example.test/search"
SCOPE_FULL = {
    "allowed_domains": ["*.example.test"],
    "allowed_ips": [],
    "allowed_ports": [443],
    "allowed_path_prefixes": ["/"],
    "excluded_paths": [],
    "rate_limit_per_second": 20,
    "allowed_test_types": ["recon", "discovery", "sqli", "xss"],
    "forbidden_actions": ["state_change"],
}
SCOPE_NARROW = {**SCOPE_FULL, "allowed_test_types": ["recon", "discovery"]}


def _seed(db_path: Path, scope: dict[str, object]) -> tuple[object, object]:
    target_id = uuid4()
    run_id = uuid4()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (str(target_id), "t", json.dumps([BASE_URL]), json.dumps(scope), 1, 0.50, datetime.now(UTC).isoformat()),
        )
        db.execute(
            "INSERT INTO runs (id, target_id, state, created_at, config) VALUES (?, ?, 'signals', ?, ?)",
            (str(run_id), str(target_id), datetime.now(UTC).isoformat(), json.dumps({})),
        )
    return target_id, run_id


def test_limiter_burst_and_isolation() -> None:
    limiter = RateLimiter(rate_per_second=5)
    assert limiter.burst == 5

    async def _burst() -> None:
        for _ in range(5):
            await limiter.acquire("a.test")

    async def _overflow() -> float:
        import time

        start = time.monotonic()
        for _ in range(6):
            await limiter.acquire("b.test")
        return time.monotonic() - start

    asyncio.run(_burst())
    assert asyncio.run(_overflow()) >= 0.15


def test_diff_signals() -> None:
    from app.testing.models import CapturedResponse

    base = CapturedResponse(url=BASE_URL, status_code=200, length=100, headers={}, body=b"hello", elapsed_ms=50)
    mutated = CapturedResponse(url=BASE_URL, status_code=500, length=500, headers={}, body=b"You have an error in your SQL syntax", elapsed_ms=60)
    diff = TestExecutor.diff(base, mutated, SQLI_ERROR_MARKERS)
    assert diff.status_changed and diff.markers and not diff.timing_anomaly
    slow = CapturedResponse(url=BASE_URL, status_code=200, length=100, headers={}, body=b"hello", elapsed_ms=3000)
    assert TestExecutor.diff(base, slow).timing_anomaly


def test_diff_timing_adapts_to_slow_baseline() -> None:
    from app.testing.models import CapturedResponse

    sluggish = CapturedResponse(url=BASE_URL, status_code=200, length=100, headers={}, body=b"hello", elapsed_ms=2000)
    modest = CapturedResponse(url=BASE_URL, status_code=200, length=100, headers={}, body=b"hello", elapsed_ms=4000)
    assert not TestExecutor.diff(sluggish, modest).timing_anomaly
    delayed = CapturedResponse(url=BASE_URL, status_code=200, length=100, headers={}, body=b"hello", elapsed_ms=9000)
    assert TestExecutor.diff(sluggish, delayed).timing_anomaly


def test_run_probe_records_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    executor = TestExecutor(db_path, tmp_path / "artifacts")
    probe = Probe(module="sqli", kind="error-based", param="q", payload="'")
    action_id = uuid4()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(BASE_URL, params={"q": "hello"}).mock(return_value=httpx.Response(200, text="results"))
        mock.get(BASE_URL, params={"q": "'"}).mock(return_value=httpx.Response(200, text="You have an error in your SQL syntax"))
        outcome = asyncio.run(executor.run_probe(action_id, None, BASE_URL, "q", "hello", probe, SQLI_ERROR_MARKERS))
    assert outcome.signals and outcome.diff.markers
    with connection(db_path) as db:
        row = db.execute("SELECT kind FROM evidence WHERE test_action_id = ?", (str(action_id),)).fetchone()
    assert row is not None and row["kind"] == "diff"
    assert list((tmp_path / "artifacts").glob(f"{action_id}-*.raw"))


def test_modules_and_context() -> None:
    assert len(sqli_probes("id")) == 8
    assert len(xss_probes("q")) == 5
    assert classify_context("no marker here") == "absent"
    assert classify_context(f"<p>{CANARY}</p>") == "raw"
    assert classify_context(f'<input value="{CANARY}>') == "attribute"
    assert classify_context(f"<script>var x='{CANARY}';</script>") == "js-string"
    assert classify_context(f"<p>&lt;{CANARY}&gt;</p>") == "encoded"


def test_sqlmap_adapter_shape_and_parse() -> None:
    command = build_command("https://app.example.test/item?id=1", "id", Path("out"))
    assert command.argv[:4] == ("sqlmap", "--batch", "--level=2", "--risk=1")
    assert "-p" in command.argv and "id" in command.argv
    findings = parse_output(b"parameter 'id' is 'MySQL >= 5.0 boolean-based blind' injectable")
    assert findings == (SqlmapFinding(parameter="id", detail="'MySQL >= 5.0 boolean-based blind' injectable"),)
    assert parse_output(b"nothing here") == ()


def test_sqlmap_execute_missing_binary(monkeypatch: object, tmp_path: Path) -> None:
    import subprocess

    def _missing(*args: object, **kwargs: object) -> object:
        raise FileNotFoundError("no sqlmap")

    monkeypatch.setattr(subprocess, "run", _missing)  # type: ignore[attr-defined]
    from app.testing.adapters.sqlmap import SqlmapError

    with __import__("pytest").raises(SqlmapError):
        execute(build_command("https://app.example.test/item?id=1", "id", tmp_path))


def test_blocked_when_test_type_not_allowed(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed(db_path, SCOPE_NARROW)
    service = TestingService(db_path, tmp_path / "artifacts", sqlmap_runner=lambda cmd: SqlmapResult(findings=(), raw=b""))
    plans = [ProbePlan(url=BASE_URL, param="q", baseline_value="hello", probes=sqli_probes("q")[:2])]
    with respx.mock(assert_all_called=False):
        summary = asyncio.run(service.run_plan(run_id, plans))  # type: ignore[arg-type]
    assert summary["probed"] == 0 and summary["blocked"] == 2
    with connection(db_path) as db:
        rows = db.execute("SELECT policy_decision FROM test_actions").fetchall()
        audits = db.execute("SELECT id FROM audit_log WHERE event = 'policy_decision'").fetchall()
    assert all(row["policy_decision"] == "deny" for row in rows) and len(audits) == 2


def test_allowed_probes_execute_and_record(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    _, run_id = _seed(db_path, SCOPE_FULL)
    service = TestingService(db_path, tmp_path / "artifacts", sqlmap_runner=lambda cmd: SqlmapResult(findings=(), raw=b""))
    error_probe = Probe(module="sqli", kind="error-based", param="q", payload="'")
    plain_probe = Probe(module="xss", kind="reflected", param="q", payload=CANARY)
    plans = [ProbePlan(url=BASE_URL, param="q", baseline_value="hello", probes=[error_probe, plain_probe])]
    with respx.mock(assert_all_called=False) as mock:
        mock.get(BASE_URL, params={"q": "hello"}).mock(return_value=httpx.Response(200, text="results page"))
        mock.get(BASE_URL, params={"q": "'"}).mock(return_value=httpx.Response(200, text="Warning: mysql_fetch_array() error"))
        mock.get(BASE_URL, params={"q": CANARY}).mock(return_value=httpx.Response(200, text=f"echo {CANARY}"))
        summary = asyncio.run(service.run_plan(run_id, plans))  # type: ignore[arg-type]
    assert summary["probed"] == 2 and summary["blocked"] == 0 and summary["signals"] >= 2
    with connection(db_path) as db:
        evidence = db.execute("SELECT kind FROM evidence").fetchall()
        actions = db.execute("SELECT policy_decision FROM test_actions").fetchall()
    assert len(evidence) >= 2 and all(row["policy_decision"] == "allow" for row in actions)

"""Orchestrator phase tests with stubbed tool services (no Kali tools needed)."""
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.db import connection, initialise_database
from app.core.schemas import RunState
from app.discovery.models import DiscoveryResult, DiscoveredEndpoint
from app.orchestrator.service import RunService
from app.recon.models import ApplicationProfile, ReconResult

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


class StubRecon:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def nmap(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
        self.calls.append(("nmap", str(run_id) if run_id else None))
        return ReconResult(hosts=(), warnings=())

    def httpx(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
        self.calls.append(("httpx", str(run_id) if run_id else None))
        return ReconResult(probes=(), warnings=())

    def summarize(self, target_id, prompt_version="recon_summary.v1"):  # type: ignore[no-untyped-def]
        return ApplicationProfile(
            tech_stack=("nginx",),
            entry_points=("id",),
            auth_surfaces=(),
            api_indicators=("https://app.example.test/api/v1/items",),
            notes="stub",
        )


class StubDiscovery:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def katana(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
        self.calls.append("katana")
        return DiscoveryResult(
            endpoints=(DiscoveredEndpoint(url="https://app.example.test/api/v1/items", source="katana"),),
            warnings=(),
        )

    def ffuf(self, target_id, base_url, wordlist_path, run_id=None):  # type: ignore[no-untyped-def]
        self.calls.append("ffuf")
        return DiscoveryResult(endpoints=(), warnings=())


def _seed_target(db_path: Path, archived: bool = False):  # type: ignore[no-untyped-def]
    from uuid import UUID  # noqa: F401
    target_id = uuid4()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(target_id),
                "juice",
                json.dumps([BASE_URL]),
                json.dumps(SCOPE),
                1,
                0.50,
                datetime.now(UTC).isoformat(),
                int(archived),
            ),
        )
    return target_id


def test_recon_discovery_happy_path(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)
    runs = RunService(db_path, tmp_path / "artifacts", StubRecon(), StubDiscovery())  # type: ignore[arg-type]
    run = runs.create_run(target_id)
    recon_out = runs.start_recon(run.id, BASE_URL)
    assert recon_out["state"] == RunState.RECON.value
    assert runs.get_run(run.id).state is RunState.RECON
    assert (db_path.parent / "backups" / f"{run.id}.db").exists()
    disc_out = runs.start_discovery(run.id, BASE_URL)
    assert disc_out["state"] == RunState.SIGNALS.value
    assert disc_out["skipped_ffuf"] is True
    assert runs.get_run(run.id).state is RunState.SIGNALS


def test_recon_wrong_state_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)
    runs = RunService(db_path, tmp_path / "artifacts", StubRecon(), StubDiscovery())  # type: ignore[arg-type]
    run = runs.create_run(target_id)
    with pytest.raises(ValueError):
        runs.start_discovery(run.id, BASE_URL)


def test_archived_target_refuses_runs(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path, archived=True)
    runs = RunService(db_path, tmp_path / "artifacts", StubRecon(), StubDiscovery())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        runs.create_run(target_id)


def test_recon_failure_leaves_audit(tmp_path: Path) -> None:
    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)

    class FailingRecon(StubRecon):
        def nmap(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
            raise PermissionError("Recon blocked by policy: Host is outside configured scope.")

    runs = RunService(db_path, tmp_path / "artifacts", FailingRecon(), StubDiscovery())  # type: ignore[arg-type]
    run = runs.create_run(target_id)
    with pytest.raises(PermissionError):
        runs.start_recon(run.id, "https://outside.test/")
    with connection(db_path) as db:
        failures = db.execute("SELECT id FROM audit_log WHERE event = 'run_failed'").fetchall()
        completed = db.execute("SELECT id FROM tool_runs WHERE status = 'completed'").fetchall()
    assert len(failures) == 1
    assert completed == []


def test_summarize_persists_profile(tmp_path: Path) -> None:
    from app.recon.service import ReconService

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = _seed_target(db_path)
    recon = ReconService(db_path, tmp_path / "artifacts")
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO endpoints (id, target_id, url, method, params, form_fields, is_api, source, first_seen) VALUES (?, ?, ?, 'GET', ?, ?, ?, 'katana', ?)",
            (
                str(uuid4()),
                str(target_id),
                "https://app.example.test/api/v1/items",
                json.dumps(["id"]),
                json.dumps([]),
                1,
                datetime.now(UTC).isoformat(),
            ),
        )
    profile = recon.summarize(target_id)
    assert "https://app.example.test/api/v1/items" in profile.api_indicators
    with connection(db_path) as db:
        row = db.execute("SELECT tech_stack FROM app_profiles WHERE target_id = ?", (str(target_id),)).fetchone()
    assert row is not None

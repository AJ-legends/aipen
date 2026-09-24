"""API-level recon/discovery tests (stubbed orchestrator services)."""
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.routes import build_router
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
    def nmap(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
        return ReconResult(hosts=(), warnings=())

    def httpx(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
        return ReconResult(probes=(), warnings=())

    def summarize(self, target_id, prompt_version="recon_summary.v1"):  # type: ignore[no-untyped-def]
        return ApplicationProfile(tech_stack=(), entry_points=(), auth_surfaces=(), api_indicators=(), notes="stub")


class StubDiscovery:
    def katana(self, target_id, base_url, run_id=None):  # type: ignore[no-untyped-def]
        return DiscoveryResult(
            endpoints=(DiscoveredEndpoint(url="https://app.example.test/p", source="katana"),), warnings=()
        )

    def ffuf(self, target_id, base_url, wordlist_path, run_id=None):  # type: ignore[no-untyped-def]
        return DiscoveryResult(endpoints=(), warnings=())


def _client(tmp_path: Path) -> tuple[TestClient, object]:
    from fastapi import FastAPI

    db_path = tmp_path / "aipen.db"
    initialise_database(db_path)
    target_id = uuid4()
    with connection(db_path) as db:
        db.execute(
            "INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (str(target_id), "t", json.dumps([BASE_URL]), json.dumps(SCOPE), 1, 0.50, datetime.now(UTC).isoformat()),
        )
    runs = RunService(db_path, tmp_path / "artifacts", StubRecon(), StubDiscovery())  # type: ignore[arg-type]
    run = runs.create_run(target_id)

    from fastapi import APIRouter

    app = FastAPI()
    router: APIRouter = build_router(db_path)
    # Swap in stubbed RunService instance
    router.routes.clear()  # type: ignore[attr-defined]
    from app.api import routes as route_module

    original = route_module.RunService
    route_module.RunService = lambda _p: runs  # type: ignore[assignment]
    try:
        router = build_router(db_path)
    finally:
        route_module.RunService = original
    app.include_router(router)
    return TestClient(app), run


def test_recon_discovery_endpoints(tmp_path: Path) -> None:
    client, run = _client(tmp_path)
    resp = client.post(f"/api/runs/{run.id}/recon", json={"base_url": BASE_URL})
    assert resp.status_code == 202, resp.text
    resp = client.post(f"/api/runs/{run.id}/discovery", json={"base_url": BASE_URL})
    assert resp.status_code == 202, resp.text
    assert resp.json()["state"] == RunState.SIGNALS.value
    resp = client.get(f"/api/runs/{run.id}")
    assert resp.status_code == 200


def test_recon_invalid_state_conflict(tmp_path: Path) -> None:
    client, run = _client(tmp_path)
    resp = client.post(f"/api/runs/{run.id}/discovery", json={"base_url": BASE_URL})
    assert resp.status_code == 409

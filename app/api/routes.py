from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, HttpUrl

from app.core.db import connection, json_value
from app.core.schemas import AppProfile, TargetCreate, TargetSummary
from app.orchestrator import RunService
from app.recon.runner import ToolExecutionError


class ReconRequest(BaseModel):
    base_url: HttpUrl


class DiscoveryRequest(BaseModel):
    base_url: HttpUrl
    wordlist_path: str | None = None


def build_router(database_path: Path) -> APIRouter:
    router = APIRouter(prefix="/api")
    runs = RunService(database_path)

    @router.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "aipen"}

    @router.get("/targets", response_model=list[TargetSummary])
    def list_targets() -> list[TargetSummary]:
        with connection(database_path) as db:
            rows = db.execute("SELECT id, name, base_urls, archived, created_at FROM targets ORDER BY created_at DESC").fetchall()
        import json
        return [TargetSummary(id=row["id"], name=row["name"], base_urls=json.loads(row["base_urls"]), archived=bool(row["archived"]), created_at=datetime.fromisoformat(row["created_at"])) for row in rows]

    @router.post("/targets", response_model=TargetSummary, status_code=status.HTTP_201_CREATED)
    def create_target(payload: TargetCreate) -> TargetSummary:
        target_id = uuid4()
        created_at = datetime.now(UTC)
        base_urls = [str(url) for url in payload.base_urls]
        with connection(database_path) as db:
            db.execute("INSERT INTO targets (id, name, base_urls, scope_config, hitl_enabled, budget_cap_usd, created_at, archived) VALUES (?, ?, ?, ?, ?, ?, ?, 0)", (str(target_id), payload.name, json_value(base_urls), json_value(payload.scope.model_dump()), int(payload.hitl_enabled), payload.budget_cap_usd, created_at.isoformat()))
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (created_at.isoformat(), "operator", "target_created", json_value({"target_id": str(target_id)})))
        return TargetSummary(id=target_id, name=payload.name, base_urls=base_urls, archived=False, created_at=created_at)

    @router.post("/targets/{target_id}/runs", status_code=status.HTTP_201_CREATED)
    def create_run(target_id: UUID) -> dict[str, object]:
        try:
            return runs.create_run(target_id).model_dump(mode="json")
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @router.get("/runs/{run_id}")
    def get_run(run_id: UUID) -> dict[str, object]:
        try:
            return runs.get_run(run_id).model_dump(mode="json")
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @router.post("/runs/{run_id}/recon", status_code=status.HTTP_202_ACCEPTED)
    def start_recon(run_id: UUID, payload: ReconRequest) -> dict[str, object]:
        try:
            return runs.start_recon(run_id, str(payload.base_url))
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except PermissionError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except ToolExecutionError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error

    @router.post("/runs/{run_id}/discovery", status_code=status.HTTP_202_ACCEPTED)
    def start_discovery(run_id: UUID, payload: DiscoveryRequest) -> dict[str, object]:
        try:
            return runs.start_discovery(run_id, str(payload.base_url), payload.wordlist_path)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except PermissionError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except ToolExecutionError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error

    @router.get("/targets/{target_id}/hosts")
    def list_hosts(target_id: UUID) -> list[dict[str, object]]:
        with connection(database_path) as db:
            exists = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            host_rows = db.execute("SELECT id, ip, hostname, source, first_seen FROM hosts WHERE target_id = ?", (str(target_id),)).fetchall()
            result: list[dict[str, object]] = []
            for host_row in host_rows:
                service_rows = db.execute(
                    "SELECT port, protocol, name, product, version, banner FROM services WHERE host_id = ?",
                    (host_row["id"],),
                ).fetchall()
                result.append(
                    {
                        "id": host_row["id"],
                        "ip": host_row["ip"],
                        "hostname": host_row["hostname"],
                        "source": host_row["source"],
                        "first_seen": host_row["first_seen"],
                        "services": [dict(row) for row in service_rows],
                    }
                )
        return result

    @router.get("/targets/{target_id}/endpoints")
    def list_endpoints(target_id: UUID, source: str | None = None) -> list[dict[str, object]]:
        import json

        with connection(database_path) as db:
            exists = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            if source:
                rows = db.execute(
                    "SELECT id, url, method, params, form_fields, is_api, source, first_seen FROM endpoints WHERE target_id = ? AND source = ? ORDER BY first_seen DESC",
                    (str(target_id), source),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT id, url, method, params, form_fields, is_api, source, first_seen FROM endpoints WHERE target_id = ? ORDER BY first_seen DESC",
                    (str(target_id),),
                ).fetchall()
        return [
            {
                "id": row["id"],
                "url": row["url"],
                "method": row["method"],
                "params": json.loads(row["params"]),
                "form_fields": json.loads(row["form_fields"]),
                "is_api": bool(row["is_api"]),
                "source": row["source"],
                "first_seen": row["first_seen"],
            }
            for row in rows
        ]

    @router.get("/targets/{target_id}/profiles/latest", response_model=AppProfile)
    def latest_profile(target_id: UUID) -> AppProfile:
        import json

        with connection(database_path) as db:
            row = db.execute(
                "SELECT id, target_id, tech_stack, entry_points, auth_surfaces, api_indicators, notes, model, prompt_version, created_at FROM app_profiles WHERE target_id = ? ORDER BY created_at DESC LIMIT 1",
                (str(target_id),),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="No profile for target.")
        return AppProfile(
            id=row["id"],
            target_id=row["target_id"],
            tech_stack=json.loads(row["tech_stack"]),
            entry_points=json.loads(row["entry_points"]),
            auth_surfaces=json.loads(row["auth_surfaces"]),
            api_indicators=json.loads(row["api_indicators"]),
            notes=row["notes"],
            model=row["model"],
            prompt_version=row["prompt_version"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    return router

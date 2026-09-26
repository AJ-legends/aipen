import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from app.core.db import connection, json_value
from app.core.schemas import AppProfile, RunState, ScopeConfig, TargetCreate, TargetSummary
from app.orchestrator import RunService

logger = logging.getLogger(__name__)


class ReconRequest(BaseModel):
    base_url: HttpUrl


class DiscoveryRequest(BaseModel):
    base_url: HttpUrl
    wordlist_path: str | None = None


from typing import Literal

TestModule = Literal["sqli", "xss"]


class TestRequest(BaseModel):
    modules: list[TestModule] = ["sqli", "xss"]
    max_probes: int = Field(default=20, ge=1, le=200)


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

    @router.patch("/targets/{target_id}/scope")
    def update_scope(target_id: UUID, payload: ScopeConfig) -> dict[str, object]:
        with connection(database_path) as db:
            target = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if target is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            active = db.execute(
                "SELECT id FROM runs WHERE target_id = ? AND state NOT IN ('created', 'completed', 'aborted')",
                (str(target_id),),
            ).fetchone()
            if active is not None:
                raise HTTPException(status_code=409, detail="Scope cannot change while a run is active.")
            now = datetime.now(UTC).isoformat()
            db.execute("UPDATE targets SET scope_config = ? WHERE id = ?", (json_value(payload.model_dump()), str(target_id)))
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (now, "operator", "scope_updated", json_value({"target_id": str(target_id)})),
            )
        return {"target_id": str(target_id), "scope": payload.model_dump()}

    @router.get("/runs/{run_id}")
    def get_run(run_id: UUID) -> dict[str, object]:
        try:
            return runs.get_run(run_id).model_dump(mode="json")
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @router.post("/runs/{run_id}/recon", status_code=status.HTTP_202_ACCEPTED)
    def start_recon(run_id: UUID, payload: ReconRequest, background: BackgroundTasks) -> dict[str, object]:
        try:
            run = runs.get_run(run_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        if run.state is not RunState.CREATED:
            raise HTTPException(status_code=409, detail=f"Recon requires CREATED state, run is {run.state.value}.")
        base_url = str(payload.base_url)

        def _do_recon() -> None:
            try:
                runs.start_recon(run_id, base_url)
            except Exception:
                logger.exception("Background recon failed for run %s", run_id)

        background.add_task(_do_recon)
        return {"run_id": str(run_id), "state": "queued", "phase": RunState.RECON.value}

    @router.post("/runs/{run_id}/discovery", status_code=status.HTTP_202_ACCEPTED)
    def start_discovery(run_id: UUID, payload: DiscoveryRequest, background: BackgroundTasks) -> dict[str, object]:
        try:
            run = runs.get_run(run_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        if run.state is not RunState.RECON:
            raise HTTPException(status_code=409, detail=f"Discovery requires RECON state, run is {run.state.value}.")
        base_url = str(payload.base_url)
        wordlist_path = payload.wordlist_path

        def _do_discovery() -> None:
            try:
                runs.start_discovery(run_id, base_url, wordlist_path)
            except Exception:
                logger.exception("Background discovery failed for run %s", run_id)

        background.add_task(_do_discovery)
        return {"run_id": str(run_id), "state": "queued", "phase": RunState.DISCOVERY.value}

    @router.post("/runs/{run_id}/test", status_code=status.HTTP_202_ACCEPTED)
    def start_testing(run_id: UUID, payload: TestRequest, background: BackgroundTasks) -> dict[str, object]:
        try:
            run = runs.get_run(run_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        if run.state is not RunState.SIGNALS:
            raise HTTPException(status_code=409, detail=f"Testing requires SIGNALS state, run is {run.state.value}.")
        modules = tuple(payload.modules)
        max_probes = payload.max_probes

        def _do_testing() -> None:
            try:
                runs.start_testing(run_id, modules, max_probes)
            except Exception:
                logger.exception("Background testing failed for run %s", run_id)

        background.add_task(_do_testing)
        return {"run_id": str(run_id), "state": "queued", "phase": RunState.ACT.value}

    @router.get("/targets/{target_id}/evidence")
    def list_evidence(target_id: UUID, run_id: UUID | None = None) -> list[dict[str, object]]:
        import json

        with connection(database_path) as db:
            exists = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            if run_id is not None:
                rows = db.execute(
                    "SELECT e.id, e.test_action_id, e.kind, e.artifact_ref, e.analysis, e.created_at, t.type, t.run_id "
                    "FROM evidence e JOIN test_actions t ON e.test_action_id = t.id "
                    "WHERE t.target_id = ? AND t.run_id = ? ORDER BY e.created_at DESC",
                    (str(target_id), str(run_id)),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT e.id, e.test_action_id, e.kind, e.artifact_ref, e.analysis, e.created_at, t.type, t.run_id "
                    "FROM evidence e JOIN test_actions t ON e.test_action_id = t.id "
                    "WHERE t.target_id = ? ORDER BY e.created_at DESC",
                    (str(target_id),),
                ).fetchall()
        return [
            {
                "id": row["id"],
                "test_action_id": row["test_action_id"],
                "kind": row["kind"],
                "artifact_ref": row["artifact_ref"],
                "analysis": json.loads(row["analysis"]),
                "created_at": row["created_at"],
                "module": row["type"],
                "run_id": row["run_id"],
            }
            for row in rows
        ]

    @router.post("/runs/{run_id}/signals", status_code=status.HTTP_202_ACCEPTED)
    def start_signals(run_id: UUID, payload: ReconRequest, background: BackgroundTasks) -> dict[str, object]:
        try:
            run = runs.get_run(run_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        if run.state is not RunState.SIGNALS:
            raise HTTPException(status_code=409, detail=f"Signals requires SIGNALS state, run is {run.state.value}.")
        base_url = str(payload.base_url)

        def _do_signals() -> None:
            try:
                runs.start_signals(run_id, base_url)
            except Exception:
                logger.exception("Background signals failed for run %s", run_id)

        background.add_task(_do_signals)
        return {"run_id": str(run_id), "state": "queued", "phase": RunState.SIGNALS.value}

    @router.post("/runs/{run_id}/analyze", status_code=status.HTTP_202_ACCEPTED)
    def start_analysis(run_id: UUID, background: BackgroundTasks) -> dict[str, object]:
        try:
            run = runs.get_run(run_id)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        if run.state is not RunState.VERIFY:
            raise HTTPException(status_code=409, detail=f"Analysis requires VERIFY state, run is {run.state.value}.")

        def _do_analysis(target_run_id: UUID) -> None:
            try:
                runs.start_analysis(target_run_id)
            except Exception:
                logger.exception("Background analysis failed for run %s", target_run_id)

        background.add_task(_do_analysis, run_id)
        return {"run_id": str(run_id), "state": "queued", "phase": RunState.ANALYZE.value}

    @router.get("/targets/{target_id}/hypotheses")
    def list_hypotheses(target_id: UUID, run_id: UUID | None = None) -> list[dict[str, object]]:
        import json

        with connection(database_path) as db:
            exists = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            query = "SELECT id, run_id, endpoint_url, vuln_class, rationale, confidence, author, status, evidence_ids, followups, created_at FROM hypotheses WHERE target_id = ?"
            args: tuple[str, ...] = (str(target_id),)
            if run_id is not None:
                query += " AND run_id = ?"
                args = (str(target_id), str(run_id))
            rows = db.execute(query + " ORDER BY created_at DESC", args).fetchall()
        return [
            {**dict(row), "evidence_ids": json.loads(row["evidence_ids"])}
            for row in rows
        ]

    @router.get("/targets/{target_id}/findings")
    def list_findings(target_id: UUID, run_id: UUID | None = None) -> list[dict[str, object]]:
        import json

        with connection(database_path) as db:
            exists = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            query = "SELECT id, run_id, hypothesis_id, verification_id, title, severity, endpoint_url, description, repro, impact, remediation, confidence, created_at FROM findings WHERE target_id = ?"
            args: tuple[str, ...] = (str(target_id),)
            if run_id is not None:
                query += " AND run_id = ?"
                args = (str(target_id), str(run_id))
            rows = db.execute(query + " ORDER BY created_at DESC", args).fetchall()
        return [
            {**dict(row), "repro": json.loads(row["repro"])}
            for row in rows
        ]

    @router.get("/targets/{target_id}/signals")
    def list_signals(target_id: UUID, run_id: UUID | None = None) -> list[dict[str, object]]:
        with connection(database_path) as db:
            exists = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if exists is None:
                raise HTTPException(status_code=404, detail="Target does not exist.")
            query = "SELECT id, run_id, endpoint_url, tool, template_id, name, severity_hint, created_at FROM signals WHERE target_id = ?"
            args: tuple[str, ...] = (str(target_id),)
            if run_id is not None:
                query += " AND run_id = ?"
                args = (str(target_id), str(run_id))
            rows = db.execute(query + " ORDER BY created_at DESC", args).fetchall()
        return [dict(row) for row in rows]

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

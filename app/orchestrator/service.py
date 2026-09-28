import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from app.ai.loop import LoopService
from app.core.db import connection, json_value
from app.core.schemas import RunState, RunSummary
from app.discovery.service import DiscoveryService
from app.recon.models import ApplicationProfile
from app.recon.service import ReconService
from app.signals.service import SignalService
from app.testing.service import TestingService


class RunService:
    """Persists safe run state and drives RECON -> DISCOVERY -> SIGNALS transitions."""

    def __init__(
        self,
        database_path: Path,
        artifacts_dir: Path | None = None,
        recon: ReconService | None = None,
        discovery: DiscoveryService | None = None,
        testing: TestingService | None = None,
        signals: SignalService | None = None,
        loop: LoopService | None = None,
        gateway: object | None = None,
    ) -> None:
        from app.ai.gateway import AIGateway

        self.database_path = database_path
        self.artifacts_dir = artifacts_dir or (database_path.parent / "artifacts")
        self.recon = recon or ReconService(database_path, self.artifacts_dir)
        self.discovery = discovery or DiscoveryService(database_path, self.artifacts_dir)
        self.testing = testing or TestingService(database_path, self.artifacts_dir)
        self.signals = signals or SignalService(database_path, self.artifacts_dir)
        resolved_gateway = gateway if isinstance(gateway, AIGateway) else AIGateway(database_path)
        self.loop = loop or LoopService(database_path, self.artifacts_dir, self.testing, resolved_gateway)

    def create_run(self, target_id: UUID) -> RunSummary:
        run_id = uuid4()
        created_at = datetime.now(UTC)
        with connection(self.database_path) as db:
            target = db.execute("SELECT archived FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if target is None:
                raise LookupError("Target does not exist.")
            if target["archived"]:
                raise ValueError("Archived targets cannot receive new runs.")
            db.execute(
                "INSERT INTO runs (id, target_id, state, created_at, config) VALUES (?, ?, ?, ?, ?)",
                (str(run_id), str(target_id), RunState.CREATED.value, created_at.isoformat(), json_value({})),
            )
        return RunSummary(id=run_id, target_id=target_id, state=RunState.CREATED, iteration=0, budget_spent_usd=0, created_at=created_at)

    def transition(self, run_id: UUID, next_state: RunState) -> None:
        with connection(self.database_path) as db:
            exists = db.execute("SELECT id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
            if exists is None:
                raise LookupError("Run does not exist.")
            db.execute("UPDATE runs SET state = ? WHERE id = ?", (next_state.value, str(run_id)))
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), "system", "run_transition", json_value({"run_id": str(run_id), "state": next_state.value})),
            )

    def get_run(self, run_id: UUID) -> RunSummary:
        with connection(self.database_path) as db:
            row = db.execute(
                "SELECT id, target_id, state, iteration, budget_spent_usd, created_at FROM runs WHERE id = ?",
                (str(run_id),),
            ).fetchone()
        if row is None:
            raise LookupError("Run does not exist.")
        return RunSummary(
            id=UUID(row["id"]),
            target_id=UUID(row["target_id"]),
            state=RunState(row["state"]),
            iteration=row["iteration"],
            budget_spent_usd=row["budget_spent_usd"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def start_recon(self, run_id: UUID, base_url: str) -> dict[str, object]:
        run = self.get_run(run_id)
        if run.state is not RunState.CREATED:
            raise ValueError(f"Recon requires CREATED state, run is {run.state.value}.")
        self._backup_database(run_id)
        self.transition(run_id, RunState.RECON)
        try:
            nmap_result = self.recon.nmap(run.target_id, base_url, run_id)
            httpx_result = self.recon.httpx(run.target_id, base_url, run_id)
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                    (
                        datetime.now(UTC).isoformat(),
                        "system",
                        "run_failed",
                        json_value({"run_id": str(run_id), "phase": "recon", "error": str(error)}),
                    ),
                )
            raise
        return {
            "run_id": str(run_id),
            "state": RunState.RECON.value,
            "hosts": len(nmap_result.hosts),
            "probes": len(httpx_result.probes),
            "warnings": [*nmap_result.warnings, *httpx_result.warnings],
        }

    def start_discovery(self, run_id: UUID, base_url: str, wordlist_path: str | None = None) -> dict[str, object]:
        run = self.get_run(run_id)
        if run.state is not RunState.RECON:
            raise ValueError(f"Discovery requires RECON state, run is {run.state.value}.")
        try:
            katana_result = self.discovery.katana(run.target_id, base_url, run_id)
            ffuf_count = 0
            ffuf_warnings: list[str] = []
            skipped_ffuf = False
            if wordlist_path:
                ffuf_result = self.discovery.ffuf(run.target_id, base_url, wordlist_path, run_id)
                ffuf_count = len(ffuf_result.endpoints)
                ffuf_warnings = list(ffuf_result.warnings)
            else:
                skipped_ffuf = True
            profile: ApplicationProfile = self.recon.summarize(run.target_id)
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                    (
                        datetime.now(UTC).isoformat(),
                        "system",
                        "run_failed",
                        json_value({"run_id": str(run_id), "phase": "discovery", "error": str(error)}),
                    ),
                )
            raise
        self.transition(run_id, RunState.DISCOVERY)
        self.transition(run_id, RunState.SIGNALS)
        return {
            "run_id": str(run_id),
            "state": RunState.SIGNALS.value,
            "katana_endpoints": len(katana_result.endpoints),
            "ffuf_endpoints": ffuf_count,
            "skipped_ffuf": skipped_ffuf,
            "profile": {
                "tech_stack": list(profile.tech_stack),
                "entry_points": list(profile.entry_points),
                "auth_surfaces": list(profile.auth_surfaces),
                "api_indicators": list(profile.api_indicators),
                "notes": profile.notes,
            },
            "warnings": [*katana_result.warnings, *ffuf_warnings],
        }

    def start_testing(
        self, run_id: UUID, modules: tuple[str, ...] = ("sqli", "xss"), max_probes: int = 20
    ) -> dict[str, object]:
        import asyncio

        run = self.get_run(run_id)
        if run.state is not RunState.SIGNALS:
            raise ValueError(f"Testing requires SIGNALS state, run is {run.state.value}.")
        self.transition(run_id, RunState.ACT)
        try:
            plans, plan_warnings = self.testing.plans_for_run(run_id, modules)
            summary = asyncio.run(self.testing.run_plan(run_id, plans, max_probes))
            summary["warnings"] = [*plan_warnings, *cast(list[str], summary.get("warnings", []))]
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                    (
                        datetime.now(UTC).isoformat(),
                        "system",
                        "run_failed",
                        json_value({"run_id": str(run_id), "phase": "testing", "error": str(error)}),
                    ),
                )
            raise
        if cast(int, summary.get("pending_approvals", 0)) > 0:
            self.transition(run_id, RunState.PAUSED)
            return {"run_id": str(run_id), "state": RunState.PAUSED.value, **summary}
        self.transition(run_id, RunState.VERIFY)
        return {"run_id": str(run_id), "state": RunState.VERIFY.value, **summary}

    def continue_testing(self, run_id: UUID) -> dict[str, object]:
        import asyncio

        run = self.get_run(run_id)
        if run.state is not RunState.PAUSED:
            raise ValueError(f"Continue requires PAUSED state, run is {run.state.value}.")
        try:
            summary = asyncio.run(self.testing.execute_approved(run_id))
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                    (
                        datetime.now(UTC).isoformat(),
                        "system",
                        "run_failed",
                        json_value({"run_id": str(run_id), "phase": "testing-continue", "error": str(error)}),
                    ),
                )
            raise
        self.transition(run_id, RunState.VERIFY)
        return {"run_id": str(run_id), "state": RunState.VERIFY.value, **summary}

    def start_signals(self, run_id: UUID, base_url: str) -> dict[str, object]:
        run = self.get_run(run_id)
        if run.state is not RunState.SIGNALS:
            raise ValueError(f"Signals requires SIGNALS state, run is {run.state.value}.")
        try:
            result = self.signals.nuclei(run.target_id, base_url, run_id)
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                    (
                        datetime.now(UTC).isoformat(),
                        "system",
                        "run_failed",
                        json_value({"run_id": str(run_id), "phase": "signals", "error": str(error)}),
                    ),
                )
            raise
        return {"run_id": str(run_id), "state": RunState.SIGNALS.value, "signals": len(result.signals), "warnings": list(result.warnings)}

    def start_analysis(self, run_id: UUID, use_ai: bool = False) -> dict[str, object]:
        import asyncio

        run = self.get_run(run_id)
        if run.state is not RunState.VERIFY:
            raise ValueError(f"Analysis requires VERIFY state, run is {run.state.value}.")
        self.transition(run_id, RunState.ANALYZE)
        try:
            summary = asyncio.run(self.loop.analyze_run(run_id, use_ai=use_ai))
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                    (
                        datetime.now(UTC).isoformat(),
                        "system",
                        "run_failed",
                        json_value({"run_id": str(run_id), "phase": "analysis", "error": str(error)}),
                    ),
                )
            raise
        self.transition(run_id, RunState.REPORTING)
        return {"run_id": str(run_id), "state": RunState.REPORTING.value, **summary}

    def _backup_database(self, run_id: UUID) -> None:
        if not self.database_path.exists():
            return
        backup_dir = self.database_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        try:
            backup_dir.chmod(0o700)
        except OSError:
            pass
        destination = backup_dir / f"{run_id}.db"
        # Online backup API: safe against WAL checkpoints, unlike a file copy.
        source = sqlite3.connect(self.database_path)
        try:
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()

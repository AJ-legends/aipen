import shutil
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from app.core.db import connection, json_value
from app.core.schemas import RunState, RunSummary
from app.discovery.service import DiscoveryService
from app.recon.models import ApplicationProfile
from app.recon.service import ReconService


class RunService:
    """Persists safe run state and drives RECON -> DISCOVERY -> SIGNALS transitions."""

    def __init__(
        self,
        database_path: Path,
        artifacts_dir: Path | None = None,
        recon: ReconService | None = None,
        discovery: DiscoveryService | None = None,
    ) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir or (database_path.parent / "artifacts")
        self.recon = recon or ReconService(database_path, self.artifacts_dir)
        self.discovery = discovery or DiscoveryService(database_path, self.artifacts_dir)

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

    def _backup_database(self, run_id: UUID) -> None:
        if not self.database_path.exists():
            return
        backup_dir = self.database_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.database_path, backup_dir / f"{run_id}.db")

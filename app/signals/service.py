"""Policy-gated signal ingestion. Signals seed hypotheses; never findings."""
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlparse
from uuid import UUID, uuid4

from pydantic import HttpUrl

from app.core.db import connection, json_value
from app.core.schemas import DecisionType, ProposedAction, RiskTier, ScopeConfig
from app.policy import check_action
from app.recon.adapters import ToolCommand
from app.recon.runner import ToolExecution, execute
from app.signals.adapters import NucleiAdapter
from app.signals.models import SignalRecord, SignalResult
from app.signals.parsers import parse_nuclei_jsonl


class SignalService:
    def __init__(self, database_path: Path, artifacts_dir: Path) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir

    def nuclei(self, target_id: UUID, base_url: str, run_id: UUID | None = None) -> SignalResult:
        scope, hitl_enabled = self._load_scope(target_id)
        action = ProposedAction(
            target_url=cast(HttpUrl, base_url),
            path=urlparse(base_url).path or "/",
            test_type="signals",
            risk_tier=RiskTier.LOW,
        )
        decision = check_action(action, scope, hitl_enabled)
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    "system",
                    "policy_decision",
                    json_value({"target_id": str(target_id), "run_id": str(run_id) if run_id else None, "action_id": str(action.id), "decision": decision.decision.value, "reason": decision.reason}),
                ),
            )
        if decision.decision is not DecisionType.ALLOW:
            raise PermissionError(f"Signals blocked by policy: {decision.reason}")
        execution = self._run_and_record("nuclei", NucleiAdapter().build_command(base_url), run_id)
        signals = parse_nuclei_jsonl(execution.stdout)
        self._save_signals(target_id, run_id, signals, execution.stdout)
        warnings = () if execution.return_code == 0 else (execution.stderr.decode("utf-8", errors="replace").strip() or f"Tool exited with {execution.return_code}",)
        return SignalResult(signals=signals, warnings=warnings)

    def _load_scope(self, target_id: UUID) -> tuple[ScopeConfig, bool]:
        with connection(self.database_path) as db:
            row = db.execute("SELECT scope_config, hitl_enabled, archived FROM targets WHERE id = ?", (str(target_id),)).fetchone()
        if row is None:
            raise LookupError("Target does not exist.")
        if row["archived"]:
            raise ValueError("Archived targets cannot be scanned.")
        return ScopeConfig.model_validate(json.loads(row["scope_config"])), bool(row["hitl_enabled"])

    def _run_and_record(self, tool: str, command: ToolCommand, run_id: UUID | None) -> ToolExecution:
        tool_run_id = uuid4()
        started_at = datetime.now(UTC)
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO tool_runs (id, run_id, tool, command, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
                (str(tool_run_id), str(run_id) if run_id else None, tool, json_value(command.argv), "running", started_at.isoformat()),
            )
        try:
            result = execute(command)
            artifact_ref = self._write_artifact(tool_run_id, tool, result.stdout)
            with connection(self.database_path) as db:
                db.execute(
                    "UPDATE tool_runs SET status = ?, artifact_ref = ?, ended_at = ? WHERE id = ?",
                    ("completed" if result.return_code == 0 else "failed", artifact_ref, datetime.now(UTC).isoformat(), str(tool_run_id)),
                )
            return result
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute("UPDATE tool_runs SET status = ?, error = ?, ended_at = ? WHERE id = ?", ("failed", str(error), datetime.now(UTC).isoformat(), str(tool_run_id)))
            raise

    def _write_artifact(self, tool_run_id: UUID, tool: str, output: bytes) -> str:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = self.artifacts_dir / f"{tool_run_id}-{tool}.raw"
        path.write_bytes(output)
        return str(path)

    def _save_signals(self, target_id: UUID, run_id: UUID | None, signals: tuple[SignalRecord, ...], raw: bytes) -> None:
        artifact_ref: str | None = None
        if signals:
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            path = self.artifacts_dir / f"{uuid4()}-nuclei-signals.raw"
            path.write_bytes(raw)
            artifact_ref = str(path)
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            for signal in signals:
                db.execute(
                    "INSERT INTO signals (id, run_id, target_id, endpoint_url, tool, template_id, name, severity_hint, raw_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid4()), str(run_id) if run_id else None, str(target_id), signal.url, "nuclei", signal.template_id, signal.name, signal.severity, artifact_ref, now),
                )

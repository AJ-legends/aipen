"""Policy-gated discovery orchestration and endpoint inventory persistence."""
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

from app.core.db import connection, json_value
from app.core.schemas import DecisionType, ProposedAction, RiskTier, ScopeConfig
from app.discovery.adapters import FfufAdapter, KatanaAdapter
from app.discovery.models import DiscoveredEndpoint, DiscoveryResult
from app.discovery.parsers import parse_ffuf_json, parse_katana_jsonl
from app.policy import check_action
from app.recon.adapters import ToolCommand
from app.recon.runner import ToolExecution, execute


class DiscoveryService:
    def __init__(self, database_path: Path, artifacts_dir: Path) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir

    def katana(self, target_id: UUID, base_url: str, run_id: UUID | None = None) -> DiscoveryResult:
        target = self._load_target(target_id)
        self._assert_allowed(target_id, base_url, target)
        execution = self._run_and_record("katana", KatanaAdapter().build_command(base_url), run_id)
        endpoints = parse_katana_jsonl(execution.stdout)
        self._save_endpoints(target_id, endpoints)
        return DiscoveryResult(endpoints=endpoints, warnings=self._warnings(execution))

    def ffuf(self, target_id: UUID, base_url: str, wordlist_path: str, run_id: UUID | None = None) -> DiscoveryResult:
        target = self._load_target(target_id)
        self._assert_allowed(target_id, base_url, target)
        execution = self._run_and_record("ffuf", FfufAdapter().build_command(base_url, wordlist_path), run_id)
        endpoints = parse_ffuf_json(execution.stdout)
        self._save_endpoints(target_id, endpoints)
        return DiscoveryResult(endpoints=endpoints, warnings=self._warnings(execution))

    def _load_target(self, target_id: UUID) -> dict[str, object]:
        with connection(self.database_path) as db:
            row = db.execute("SELECT scope_config, hitl_enabled, archived FROM targets WHERE id = ?", (str(target_id),)).fetchone()
        if row is None:
            raise LookupError("Target does not exist.")
        if row["archived"]:
            raise ValueError("Archived targets cannot be scanned.")
        return {"scope": ScopeConfig.model_validate(json.loads(row["scope_config"])), "hitl_enabled": bool(row["hitl_enabled"])}

    def _assert_allowed(self, target_id: UUID, base_url: str, target: dict[str, object]) -> None:
        action = ProposedAction(target_url=base_url, path=urlparse(base_url).path or "/", test_type="discovery", risk_tier=RiskTier.LOW)
        decision = check_action(action, target["scope"], bool(target["hitl_enabled"]))  # type: ignore[arg-type]
        with connection(self.database_path) as db:
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (datetime.now(UTC).isoformat(), "system", "policy_decision", json_value({"target_id": str(target_id), "action_id": str(action.id), "decision": decision.decision.value, "reason": decision.reason})))
        if decision.decision is not DecisionType.ALLOW:
            raise PermissionError(f"Discovery blocked by policy: {decision.reason}")

    def _run_and_record(self, tool: str, command: ToolCommand, run_id: UUID | None = None) -> ToolExecution:
        tool_run_id = uuid4()
        started_at = datetime.now(UTC)
        with connection(self.database_path) as db:
            db.execute("INSERT INTO tool_runs (id, run_id, tool, command, status, started_at) VALUES (?, ?, ?, ?, ?, ?)", (str(tool_run_id), str(run_id) if run_id else None, tool, json_value(command.argv), "running", started_at.isoformat()))
        try:
            execution = execute(command)
            artifact_ref = self._write_artifact(tool_run_id, tool, execution.stdout)
            with connection(self.database_path) as db:
                db.execute("UPDATE tool_runs SET status = ?, artifact_ref = ?, ended_at = ? WHERE id = ?", ("completed" if execution.return_code == 0 else "failed", artifact_ref, datetime.now(UTC).isoformat(), str(tool_run_id)))
            return execution
        except Exception as error:
            with connection(self.database_path) as db:
                db.execute("UPDATE tool_runs SET status = ?, error = ?, ended_at = ? WHERE id = ?", ("failed", str(error), datetime.now(UTC).isoformat(), str(tool_run_id)))
            raise

    def _write_artifact(self, tool_run_id: UUID, tool: str, output: bytes) -> str:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = self.artifacts_dir / f"{tool_run_id}-{tool}.raw"
        path.write_bytes(output)
        return str(path)

    @staticmethod
    def _warnings(execution: ToolExecution) -> tuple[str, ...]:
        if execution.return_code == 0:
            return ()
        return (execution.stderr.decode("utf-8", errors="replace").strip() or f"Tool exited with {execution.return_code}.",)

    def _save_endpoints(self, target_id: UUID, endpoints: tuple[DiscoveredEndpoint, ...]) -> None:
        with connection(self.database_path) as db:
            for endpoint in endpoints:
                db.execute("INSERT INTO endpoints (id, target_id, url, method, params, form_fields, is_api, source, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(target_id, url, method) DO UPDATE SET params = excluded.params, form_fields = excluded.form_fields, is_api = excluded.is_api", (str(uuid4()), str(target_id), endpoint.url, endpoint.method, json_value(endpoint.parameters), json_value(endpoint.form_fields), int(endpoint.is_api), endpoint.source, datetime.now(UTC).isoformat()))

"""Policy-gated, auditable reconnaissance orchestration."""
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

from app.core.db import connection, json_value
from app.core.schemas import DecisionType, ProposedAction, RiskTier, ScopeConfig
from app.policy import check_action
from app.recon.adapters import HttpxAdapter, NmapAdapter, ToolCommand
from app.recon.models import ApplicationProfile, HttpProbeRecord, HostRecord, ReconResult, ServiceRecord
from app.recon.parsers import parse_httpx_jsonl, parse_nmap_xml
from app.recon.runner import ToolExecution, execute
from app.recon.summary import build_profile


class ReconService:
    def __init__(self, database_path: Path, artifacts_dir: Path) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir

    def nmap(self, target_id: UUID, base_url: str, run_id: UUID | None = None) -> ReconResult:
        target = self._load_target(target_id)
        hostname = urlparse(base_url).hostname
        if hostname is None:
            raise ValueError("Target URL has no hostname.")
        command = NmapAdapter().build_command(hostname, target["scope"].allowed_ports)
        action = ProposedAction(target_url=base_url, path="/", test_type="recon", risk_tier=RiskTier.LOW)
        self._assert_allowed(target_id, action, target["scope"], target["hitl_enabled"])
        execution = self._run_and_record(target_id, "nmap", command, run_id)
        hosts = parse_nmap_xml(execution.stdout)
        self._save_hosts(target_id, hosts)
        return ReconResult(hosts=hosts, warnings=self._warnings(execution))

    def httpx(self, target_id: UUID, base_url: str, run_id: UUID | None = None) -> ReconResult:
        target = self._load_target(target_id)
        command = HttpxAdapter().build_command(base_url)
        action = ProposedAction(target_url=base_url, path=urlparse(base_url).path or "/", test_type="recon", risk_tier=RiskTier.LOW)
        self._assert_allowed(target_id, action, target["scope"], target["hitl_enabled"])
        execution = self._run_and_record(target_id, "httpx", command, run_id)
        probes = parse_httpx_jsonl(execution.stdout)
        self._save_probes(target_id, probes)
        return ReconResult(probes=probes, warnings=self._warnings(execution))

    def summarize(self, target_id: UUID, prompt_version: str = "recon_summary.v1") -> ApplicationProfile:
        from app.discovery.models import DiscoveredEndpoint

        with connection(self.database_path) as db:
            target = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if target is None:
                raise LookupError("Target does not exist.")
            host_rows = db.execute("SELECT id, ip, hostname FROM hosts WHERE target_id = ?", (str(target_id),)).fetchall()
            hosts: list[HostRecord] = []
            for host_row in host_rows:
                service_rows = db.execute(
                    "SELECT port, protocol, name, product, version, banner FROM services WHERE host_id = ?",
                    (host_row["id"],),
                ).fetchall()
                services = tuple(
                    ServiceRecord(
                        port=row["port"],
                        protocol=row["protocol"],
                        name=row["name"],
                        product=row["product"],
                        version=row["version"],
                        banner=row["banner"],
                    )
                    for row in service_rows
                )
                hosts.append(HostRecord(ip=host_row["ip"], hostname=host_row["hostname"], services=services))
            endpoint_rows = db.execute(
                "SELECT url, method, params, form_fields, is_api, source FROM endpoints WHERE target_id = ?",
                (str(target_id),),
            ).fetchall()
            endpoints = tuple(
                DiscoveredEndpoint(
                    url=row["url"],
                    method=row["method"],
                    parameters=tuple(json.loads(row["params"])),
                    form_fields=tuple(json.loads(row["form_fields"])),
                    is_api=bool(row["is_api"]),
                    source=row["source"],
                )
                for row in endpoint_rows
            )
        profile = build_profile(tuple(hosts), (), endpoints)
        created_at = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO app_profiles (id, target_id, tech_stack, entry_points, auth_surfaces, api_indicators, notes, prompt_version, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(target_id) DO UPDATE SET "
                "tech_stack = excluded.tech_stack, entry_points = excluded.entry_points, "
                "auth_surfaces = excluded.auth_surfaces, api_indicators = excluded.api_indicators, "
                "notes = excluded.notes, prompt_version = excluded.prompt_version, created_at = excluded.created_at",
                (
                    str(uuid4()),
                    str(target_id),
                    json_value(list(profile.tech_stack)),
                    json_value(list(profile.entry_points)),
                    json_value(list(profile.auth_surfaces)),
                    json_value(list(profile.api_indicators)),
                    profile.notes,
                    prompt_version,
                    created_at,
                ),
            )
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (created_at, "system", "recon_summarized", json_value({"target_id": str(target_id)})),
            )
        return profile

    def _load_target(self, target_id: UUID) -> dict[str, object]:
        with connection(self.database_path) as db:
            row = db.execute("SELECT scope_config, hitl_enabled, archived FROM targets WHERE id = ?", (str(target_id),)).fetchone()
        if row is None:
            raise LookupError("Target does not exist.")
        if row["archived"]:
            raise ValueError("Archived targets cannot be scanned.")
        return {"scope": ScopeConfig.model_validate(json.loads(row["scope_config"])), "hitl_enabled": bool(row["hitl_enabled"])}

    def _assert_allowed(self, target_id: UUID, action: ProposedAction, scope: ScopeConfig, hitl_enabled: bool) -> None:
        decision = check_action(action, scope, hitl_enabled)
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), "system", "policy_decision", json_value({"target_id": str(target_id), "action_id": str(action.id), "decision": decision.decision.value, "reason": decision.reason})),
            )
        if decision.decision is not DecisionType.ALLOW:
            raise PermissionError(f"Recon blocked by policy: {decision.reason}")

    def _run_and_record(self, target_id: UUID, tool: str, command: ToolCommand, run_id: UUID | None = None) -> ToolExecution:
        tool_run_id = uuid4()
        started_at = datetime.now(UTC)
        with connection(self.database_path) as db:
            db.execute("INSERT INTO tool_runs (id, run_id, tool, command, status, started_at) VALUES (?, ?, ?, ?, ?, ?)", (str(tool_run_id), str(run_id) if run_id else None, tool, json_value(command.argv), "running", started_at.isoformat()))
        try:
            result = execute(command)
            artifact_ref = self._write_artifact(tool_run_id, tool, result.stdout)
            with connection(self.database_path) as db:
                db.execute("UPDATE tool_runs SET status = ?, artifact_ref = ?, ended_at = ? WHERE id = ?", ("completed" if result.return_code == 0 else "failed", artifact_ref, datetime.now(UTC).isoformat(), str(tool_run_id)))
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

    @staticmethod
    def _warnings(execution: ToolExecution) -> tuple[str, ...]:
        if execution.return_code == 0:
            return ()
        message = execution.stderr.decode("utf-8", errors="replace").strip() or f"Tool exited with {execution.return_code}."
        return (message,)

    def _save_hosts(self, target_id: UUID, hosts: tuple[HostRecord, ...]) -> None:
        with connection(self.database_path) as db:
            for host in hosts:
                host_id = uuid4()
                db.execute("INSERT INTO hosts (id, target_id, ip, hostname, source, first_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(target_id, ip, source) DO UPDATE SET hostname = excluded.hostname", (str(host_id), str(target_id), host.ip, host.hostname, "nmap", datetime.now(UTC).isoformat()))
                row = db.execute("SELECT id FROM hosts WHERE target_id = ? AND ip = ? AND source = ?", (str(target_id), host.ip, "nmap")).fetchone()
                for service in host.services:
                    db.execute("INSERT INTO services (id, host_id, port, protocol, name, product, version, banner) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(host_id, port, protocol) DO UPDATE SET name = excluded.name, product = excluded.product, version = excluded.version, banner = excluded.banner", (str(uuid4()), row["id"], service.port, service.protocol, service.name, service.product, service.version, service.banner))

    def _save_probes(self, target_id: UUID, probes: tuple[HttpProbeRecord, ...]) -> None:
        with connection(self.database_path) as db:
            for probe in probes:
                db.execute("INSERT INTO endpoints (id, target_id, url, method, is_api, source, first_seen) VALUES (?, ?, ?, 'GET', ?, 'httpx', ?) ON CONFLICT(target_id, url, method) DO NOTHING", (str(uuid4()), str(target_id), probe.url, int("/api/" in probe.url), datetime.now(UTC).isoformat()))

"""Policy-gated differential testing orchestration (S3: SQLi + XSS; S5: IDOR, SSRF, API)."""
import json
import os
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlparse
from uuid import UUID, uuid4

import httpx
from pydantic import HttpUrl

from app.approvals.service import ApprovalService
from app.core.db import connection, json_value
from app.core.schemas import DecisionType, PolicyDecision, ProposedAction, RiskTier, ScopeConfig
from app.policy import check_action
from app.testing.adapters.sqlmap import SqlmapCommand, SqlmapError, SqlmapResult, build_command
from app.testing.adapters.sqlmap import execute as run_sqlmap
from app.testing.executor import TestExecutor
from app.testing.models import Probe, ProbePlan
from app.testing.modules.api import VERBOSE_ERROR_MARKERS, api_probes
from app.testing.modules.idor import idor_probes, is_identifier_param
from app.testing.modules.sqli import SQLI_ERROR_MARKERS, sqli_probes
from app.testing.modules.ssrf import is_urlish_param, is_urlish_url, ssrf_probes
from app.testing.modules.xss import CANARY, classify_context, xss_probes

TEST_TYPES = ("sqli", "xss", "idor", "ssrf", "api")
MAX_ESCALATIONS = 2


class TestingService:
    __test__ = False  # not a pytest test class despite the name

    def __init__(
        self,
        database_path: Path,
        artifacts_dir: Path,
        executor: TestExecutor | None = None,
        sqlmap_runner: Callable[[SqlmapCommand], SqlmapResult] | None = None,
        approvals: ApprovalService | None = None,
        oob_base: str | None = None,
    ) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir
        self.executor = executor or TestExecutor(database_path, artifacts_dir)
        self.sqlmap_runner = sqlmap_runner or run_sqlmap
        self.approvals = approvals or ApprovalService(database_path)
        self.oob_base = oob_base if oob_base is not None else os.environ.get("AIPEN_OOB_BASE", "")

    async def run_plan(self, run_id: UUID, plans: list[ProbePlan], max_probes: int = 20) -> dict[str, object]:
        run_target = self._load_run_target(run_id)
        target_id, scope, hitl_enabled = run_target
        # Sync executor rate with the target's scope.
        self.executor.limiter.rate_per_second = scope.rate_limit_per_second
        probed = 0
        blocked = 0
        pending = 0
        signal_count = 0
        sqlmap_findings: list[dict[str, str]] = []
        escalations = 0
        warnings: list[str] = []
        for plan in plans:
            for probe in plan.probes:
                if probed >= max_probes:
                    warnings.append(f"Probe budget exhausted at {max_probes}; remaining probes skipped.")
                    return self._summary(probed, blocked, pending, signal_count, sqlmap_findings, warnings)
                outcome_decision = self._check_and_audit(run_id, target_id, plan, probe, scope, hitl_enabled)
                decision = outcome_decision.decision
                if decision == DecisionType.NEEDS_APPROVAL:
                    blocked += 1
                    pending += 1
                    action_id = self._insert_action(run_id, target_id, plan.url, probe, decision, approval="pending")
                    self.approvals.request(
                        target_id,
                        {"url": plan.url, "param": plan.param, "payload": probe.payload, "kind": probe.kind, "module": probe.module},
                        RiskTier(probe.risk_tier) if probe.risk_tier in ("low", "medium", "high") else RiskTier.MEDIUM,
                        outcome_decision.reason,
                        f"Send {probe.kind} probe to '{plan.param}' on {plan.url}",
                        run_id=run_id,
                        test_action_id=action_id,
                    )
                    continue
                if decision != DecisionType.ALLOW:
                    blocked += 1
                    self._insert_action(run_id, target_id, plan.url, probe, decision, approval="n/a")
                    continue
                if decision != DecisionType.ALLOW:
                    blocked += 1
                    self._insert_action(run_id, target_id, plan.url, probe, decision, approval="n/a")
                    continue
                action_id = self._insert_action(run_id, target_id, plan.url, probe, decision, approval="auto")
                baseline_headers, mutated_headers = self._resolve_headers(target_id, probe)
                try:
                    outcome = await self.executor.run_probe(
                        action_id, run_id, plan.url, plan.param, plan.baseline_value, probe, self._markers_for(probe),
                        baseline_headers=baseline_headers, mutated_headers=mutated_headers,
                    )
                except httpx.HTTPError as error:
                    warnings.append(f"Probe failed for {plan.param}: {error}")
                    continue
                probed += 1
                signal_count += len(outcome.signals)
                if probe.module == "xss" and CANARY in outcome.mutated.body.decode("utf-8", errors="replace"):
                    context = classify_context(outcome.mutated.body.decode("utf-8", errors="replace"))
                    self._note_context(action_id, context)
                if (
                    probe.module == "sqli"
                    and probe.kind == "error-based"
                    and outcome.diff.markers
                    and escalations < MAX_ESCALATIONS
                ):
                    escalations += 1
                    try:
                        findings = await self._escalate(action_id, plan.url, plan.param)
                        sqlmap_findings.extend(findings)
                    except (SqlmapError, ValueError, OSError) as error:
                        warnings.append(f"sqlmap escalation failed for {plan.param}: {error}")
        return self._summary(probed, blocked, pending, signal_count, sqlmap_findings, warnings)

    @staticmethod
    def _summary(probed: int, blocked: int, pending: int, signals: int, sqlmap: list[dict[str, str]], warnings: list[str]) -> dict[str, object]:
        return {"probed": probed, "blocked": blocked, "pending_approvals": pending, "signals": signals, "sqlmap_findings": sqlmap, "warnings": warnings}

    async def execute_approved(self, run_id: UUID) -> dict[str, object]:
        """Execute pending probes whose approvals were granted.

        Each probe is rebuilt with its ORIGINAL context (kind, session,
        strip_auth, risk tier) and re-checked against CURRENT policy before any
        request is sent: scope may have changed since approval was granted.
        """
        target_id, scope, hitl_enabled = self._load_run_target(run_id)
        self.executor.limiter.rate_per_second = scope.rate_limit_per_second
        with connection(self.database_path) as db:
            rows = db.execute(
                "SELECT t.id, t.type, t.payload, t.risk_tier FROM test_actions t "
                "JOIN approvals a ON a.test_action_id = t.id "
                "WHERE t.run_id = ? AND t.approval_state = 'pending' AND a.state = 'approved'",
                (str(run_id),),
            ).fetchall()
        probed = 0
        skipped = 0
        warnings: list[str] = []
        for row in rows:
            payload = json.loads(row["payload"])
            probe = Probe(
                module=row["type"],
                kind=str(payload.get("kind", "approved")),
                param=str(payload.get("param", "")),
                payload=str(payload.get("payload", "")),
                risk_tier=str(row["risk_tier"]),
                session=payload.get("session"),
                strip_auth=bool(payload.get("strip_auth", False)),
            )
            url = str(payload.get("url", ""))
            plan = ProbePlan(url=url, param=probe.param, baseline_value="", probes=[probe])
            recheck = self._check_and_audit(run_id, target_id, plan, probe, scope, hitl_enabled)
            if recheck.decision is DecisionType.DENY:
                skipped += 1
                warnings.append(f"Approved probe for '{probe.param}' now denied ({recheck.reason}); skipped.")
                continue
            # NEEDS_APPROVAL here is satisfied by the joined approval row; ALLOW proceeds directly.
            action_id = UUID(row["id"])
            baseline_headers, mutated_headers = self._resolve_headers(target_id, probe)
            try:
                await self.executor.run_probe(
                    action_id, run_id, url, probe.param, "", probe, self._markers_for(probe),
                    baseline_headers=baseline_headers, mutated_headers=mutated_headers,
                )
            except httpx.HTTPError as error:
                warnings.append(f"Approved probe failed: {error}")
                continue
            probed += 1
            with connection(self.database_path) as db:
                db.execute("UPDATE test_actions SET approval_state = 'executed' WHERE id = ?", (str(action_id),))
        return {"probed": probed, "skipped": skipped, "warnings": warnings}

    @staticmethod
    def _markers_for(probe: Probe) -> tuple[str, ...]:
        if probe.module == "sqli":
            return SQLI_ERROR_MARKERS
        if probe.module == "xss":
            return (CANARY,)
        if probe.module == "api":
            return VERBOSE_ERROR_MARKERS
        return ()

    def _resolve_headers(self, target_id: UUID, probe: Probe) -> tuple[dict[str, str] | None, dict[str, str] | None]:
        """Resolve baseline/mutated headers. Secrets stay in memory; only names persist."""
        sessions: dict[str, dict[str, str]] = {}
        for item in self._load_sessions(target_id):
            name = item.get("name")
            headers = item.get("headers")
            if isinstance(name, str) and isinstance(headers, dict):
                sessions[name] = {str(key): str(value) for key, value in headers.items()}
        if not probe.session and not probe.strip_auth:
            return None, None
        primary: dict[str, str] = next(iter(sessions.values()), {})
        if probe.strip_auth:
            return (dict(primary) or None), None
        mutated = sessions.get(probe.session or "", {})
        return (dict(primary) or None), (dict(mutated) or None)

    def _load_sessions(self, target_id: UUID) -> list[dict[str, object]]:
        try:
            with connection(self.database_path) as db:
                row = db.execute("SELECT sessions FROM targets WHERE id = ?", (str(target_id),)).fetchone()
        except sqlite3.OperationalError:
            return []
        if row is None:
            return []
        try:
            items = json.loads(str(row["sessions"] or "[]"))
        except ValueError:
            return []
        return [item for item in items if isinstance(item, dict) and isinstance(item.get("name"), str)]

    def _check_and_audit(self, run_id: UUID, target_id: UUID, plan: ProbePlan, probe: Probe, scope: ScopeConfig, hitl_enabled: bool) -> PolicyDecision:
        try:
            risk = RiskTier(probe.risk_tier)
        except ValueError:
            risk = RiskTier.HIGH
        action = ProposedAction(
            target_url=cast(HttpUrl, plan.url),
            path=urlparse(plan.url).path or "/",
            test_type=probe.module,
            risk_tier=risk,
        )
        decision = check_action(action, scope, hitl_enabled)
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    "system",
                    "policy_decision",
                    json_value({"target_id": str(target_id), "run_id": str(run_id), "action_id": str(action.id), "decision": decision.decision.value, "reason": decision.reason}),
                ),
            )
        return decision

    def _insert_action(self, run_id: UUID, target_id: UUID, url: str, probe: Probe, decision: DecisionType, approval: str) -> UUID:
        action_id = uuid4()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO test_actions (id, run_id, target_id, type, payload, risk_tier, policy_decision, approval_state, executed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(action_id),
                    str(run_id),
                    str(target_id),
                    probe.module,
                    json_value({"url": url, "param": probe.param, "payload": probe.payload, "kind": probe.kind, "session": probe.session, "strip_auth": probe.strip_auth}),
                    probe.risk_tier,
                    decision.value,
                    approval,
                    datetime.now(UTC).isoformat(),
                ),
            )
        return action_id

    def _note_context(self, action_id: UUID, context: str) -> None:
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO evidence (id, test_action_id, kind, analysis, created_at) VALUES (?, ?, ?, ?, ?)",
                (str(uuid4()), str(action_id), "analysis", json_value({"xss_context": context}), datetime.now(UTC).isoformat()),
            )

    async def _escalate(self, action_id: UUID, url: str, param: str) -> list[dict[str, str]]:
        import asyncio

        output_dir = self.artifacts_dir / "sqlmap"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = build_command(url, param, output_dir)
        result = await asyncio.to_thread(self.sqlmap_runner, command)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        artifact = self.artifacts_dir / f"sqlmap-{param}.raw"
        artifact.write_bytes(result.raw)
        findings = [{"parameter": finding.parameter, "detail": finding.detail} for finding in result.findings]
        if findings:
            with connection(self.database_path) as db:
                db.execute(
                    "INSERT INTO evidence (id, test_action_id, kind, artifact_ref, analysis, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid4()), str(action_id), "tool_output", str(artifact), json_value({"sqlmap": findings, "param": param}), datetime.now(UTC).isoformat()),
                )
        return findings

    def _load_run_target(self, run_id: UUID) -> tuple[UUID, ScopeConfig, bool]:
        with connection(self.database_path) as db:
            run = db.execute("SELECT target_id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
            if run is None:
                raise LookupError("Run does not exist.")
            target = db.execute("SELECT id, scope_config, hitl_enabled, archived FROM targets WHERE id = ?", (run["target_id"],)).fetchone()
            if target is None:
                raise LookupError("Target does not exist.")
            if target["archived"]:
                raise ValueError("Archived targets cannot be tested.")
            scope = ScopeConfig.model_validate(json.loads(target["scope_config"]))
            return UUID(target["id"]), scope, bool(target["hitl_enabled"])

    def plans_for_run(self, run_id: UUID, modules: tuple[str, ...] = TEST_TYPES, limit: int = 10) -> tuple[list[ProbePlan], list[str]]:
        """Build probe plans from the endpoint inventory (endpoints with params)."""
        with connection(self.database_path) as db:
            run = db.execute("SELECT target_id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
            if run is None:
                raise LookupError("Run does not exist.")
            rows = db.execute(
                "SELECT url, method, params FROM endpoints WHERE target_id = ? ORDER BY first_seen DESC LIMIT ?",
                (run["target_id"], limit),
            ).fetchall()
        target_id = UUID(str(run["target_id"]))
        session_names = tuple(str(item["name"]) for item in self._load_sessions(target_id))
        warnings: list[str] = []
        if "ssrf" in modules and not self.oob_base:
            warnings.append("SSRF requested but AIPEN_OOB_BASE is unset; ssrf probes skipped.")
        plans: list[ProbePlan] = []
        for row in rows:
            if row["method"].upper() != "GET":
                continue
            for param in json.loads(row["params"]):
                probes: list[Probe] = []
                if "sqli" in modules:
                    probes.extend(sqli_probes(param))
                if "xss" in modules:
                    probes.extend(xss_probes(param))
                if "idor" in modules and is_identifier_param(param):
                    probes.extend(idor_probes(param, sessions=session_names))
                if "ssrf" in modules and self.oob_base and (is_urlish_param(param) or is_urlish_url(row["url"])):
                    probes.extend(ssrf_probes(param, self.oob_base))
                if "api" in modules:
                    probes.extend(api_probes(row["url"], param, sessions=session_names))
                if probes:
                    plans.append(ProbePlan(url=row["url"], method="GET", param=param, probes=probes))
        return plans, warnings

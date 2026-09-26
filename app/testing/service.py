"""Policy-gated differential testing orchestration (S3: SQLi + XSS)."""
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlparse
from uuid import UUID, uuid4

import httpx
from pydantic import HttpUrl

from app.core.db import connection, json_value
from app.core.schemas import DecisionType, ProposedAction, RiskTier, ScopeConfig
from app.policy import check_action
from app.testing.adapters.sqlmap import SqlmapCommand, SqlmapError, SqlmapResult, build_command
from app.testing.adapters.sqlmap import execute as run_sqlmap
from app.testing.executor import TestExecutor
from app.testing.models import Probe, ProbePlan
from app.testing.modules.sqli import SQLI_ERROR_MARKERS, sqli_probes
from app.testing.modules.xss import CANARY, classify_context, xss_probes

TEST_TYPES = ("sqli", "xss")
MAX_ESCALATIONS = 2


class TestingService:
    __test__ = False  # not a pytest test class despite the name

    def __init__(
        self,
        database_path: Path,
        artifacts_dir: Path,
        executor: TestExecutor | None = None,
        sqlmap_runner: Callable[[SqlmapCommand], SqlmapResult] | None = None,
    ) -> None:
        self.database_path = database_path
        self.artifacts_dir = artifacts_dir
        self.executor = executor or TestExecutor(database_path, artifacts_dir)
        self.sqlmap_runner = sqlmap_runner or run_sqlmap

    async def run_plan(self, run_id: UUID, plans: list[ProbePlan], max_probes: int = 20) -> dict[str, object]:
        run_target = self._load_run_target(run_id)
        target_id, scope, hitl_enabled = run_target
        # Sync executor rate with the target's scope.
        self.executor.limiter.rate_per_second = scope.rate_limit_per_second
        probed = 0
        blocked = 0
        signal_count = 0
        sqlmap_findings: list[dict[str, str]] = []
        escalations = 0
        warnings: list[str] = []
        for plan in plans:
            for probe in plan.probes:
                if probed >= max_probes:
                    warnings.append(f"Probe budget exhausted at {max_probes}; remaining probes skipped.")
                    return self._summary(probed, blocked, signal_count, sqlmap_findings, warnings)
                decision = self._check_and_audit(run_id, target_id, plan, probe, scope, hitl_enabled)
                if decision != DecisionType.ALLOW:
                    blocked += 1
                    self._insert_action(run_id, target_id, plan.url, probe, decision, approval="pending" if decision == DecisionType.NEEDS_APPROVAL else "n/a")
                    continue
                action_id = self._insert_action(run_id, target_id, plan.url, probe, decision, approval="auto")
                try:
                    outcome = await self.executor.run_probe(
                        action_id, run_id, plan.url, plan.param, plan.baseline_value, probe, self._markers_for(probe)
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
        return self._summary(probed, blocked, signal_count, sqlmap_findings, warnings)

    @staticmethod
    def _summary(probed: int, blocked: int, signals: int, sqlmap: list[dict[str, str]], warnings: list[str]) -> dict[str, object]:
        return {"probed": probed, "blocked": blocked, "signals": signals, "sqlmap_findings": sqlmap, "warnings": warnings}

    @staticmethod
    def _markers_for(probe: Probe) -> tuple[str, ...]:
        if probe.module == "sqli":
            return SQLI_ERROR_MARKERS
        if probe.module == "xss":
            return (CANARY,)
        return ()

    def _check_and_audit(self, run_id: UUID, target_id: UUID, plan: ProbePlan, probe: Probe, scope: ScopeConfig, hitl_enabled: bool) -> DecisionType:
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
        return decision.decision

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
                    json_value({"url": url, "param": probe.param, "payload": probe.payload, "kind": probe.kind}),
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

    def plans_for_run(self, run_id: UUID, modules: tuple[str, ...] = TEST_TYPES, limit: int = 10) -> list[ProbePlan]:
        """Build probe plans from the endpoint inventory (endpoints with params)."""
        with connection(self.database_path) as db:
            run = db.execute("SELECT target_id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
            if run is None:
                raise LookupError("Run does not exist.")
            rows = db.execute(
                "SELECT url, method, params FROM endpoints WHERE target_id = ? ORDER BY first_seen DESC LIMIT ?",
                (run["target_id"], limit),
            ).fetchall()
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
                if probes:
                    plans.append(ProbePlan(url=row["url"], method="GET", param=param, probes=probes))
        return plans

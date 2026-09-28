"""Loop closure: observe -> reason -> verify -> (follow-up) -> finding.

Deterministic authors back the analyst/verifier contracts; model-backed
authors plug in later. Findings are created only on CONFIRM votes (I1),
enforced both here and by the ``finding_needs_confirm`` trigger.
"""
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from app.ai.analyst import EvidenceView, HypothesisDraft, SignalView, analyze_evidence
from app.ai.gateway import AIGateway, AIRole, BudgetContext
from app.ai.providers import ProviderError
from app.ai.verifier import Verdict, verify_hypothesis
from app.core.db import connection, json_value
from app.core.schemas import HypothesisStatus, VerificationVote
from app.testing.models import ProbePlan
from app.testing.modules.sqli import sqli_probes
from app.testing.modules.xss import xss_probes
from app.testing.service import TestingService

MAX_FOLLOWUPS = 2
ANALYST_VERSION = "analyst.v1"
VERIFIER_VERSION = "verifier.v1"
ALLOWED_CLASSES = ("sqli", "xss", "idor", "ssrf", "api")
MAX_AI_EVIDENCE_ITEMS = 20

CLASS_META = {
    "sqli": {
        "severity": "high",
        "impact": "Attackers may read, modify, or delete database contents and escalate toward the host.",
        "remediation": "Use parameterised queries / ORM bindings, least-privilege DB accounts, and server-side input validation.",
    },
    "xss": {
        "severity": "medium",
        "impact": "Attackers may execute script in victims' browsers (session hijacking, defacement, phishing).",
        "remediation": "Apply context-aware output encoding, validate input server-side, and deploy a Content-Security-Policy.",
    },
    "idor": {
        "severity": "high",
        "impact": "Attackers may access other users' objects by guessing identifiers (broken object-level authorization).",
        "remediation": "Enforce server-side ownership checks on every object access; use unguessable IDs and deny by default.",
    },
    "ssrf": {
        "severity": "high",
        "impact": "Attackers may make the server issue requests to internal systems or exfiltrate via out-of-band channels.",
        "remediation": "Allow-list outbound destinations, disable unused URL schemes, and validate/encode user-supplied URLs.",
    },
    "api": {
        "severity": "medium",
        "impact": "API flaws may leak data or internal details (verbose errors, BOLA) and aid further attacks.",
        "remediation": "Enforce per-object authorization, suppress stack traces in production, and validate API schemas strictly.",
    },
}


class LoopService:
    __test__ = False  # not a pytest test class despite the name

    def __init__(
        self,
        database_path: Path,
        artifacts_dir: Path,
        testing: TestingService | None = None,
        gateway: AIGateway | None = None,
    ) -> None:
        self.database_path = database_path
        self.testing = testing or TestingService(database_path, artifacts_dir)
        self.gateway = gateway

    async def analyze_run(self, run_id: UUID, use_ai: bool = False) -> dict[str, object]:
        target_id = self._run_target(run_id)
        views = self._load_evidence(run_id)
        signals = self._load_signals(run_id)
        cited = self._cited_evidence(run_id)
        fresh = tuple(view for view in views if view.id not in cited)
        new = 0
        for draft in analyze_evidence(fresh, signals):
            if self._open_exists(run_id, draft.endpoint_url, draft.vuln_class):
                continue
            self._insert_hypothesis(run_id, target_id, draft)
            new += 1
        ai_notes: list[str] = []
        budget = self._budget_for(run_id) if use_ai else None
        if use_ai and budget is not None:
            ai_drafts, note = self._ai_analyst(run_id, fresh, signals, budget)
            ai_notes.append(note)
            for draft, author in ai_drafts:
                if self._open_exists(run_id, draft.endpoint_url, draft.vuln_class):
                    continue
                self._insert_hypothesis(run_id, target_id, draft, author=author)
                new += 1
        verified = rejected = stalled = 0
        findings: list[str] = []
        for hypothesis in self._open_hypotheses(run_id):
            outcome = await self._settle(run_id, target_id, hypothesis, use_ai=use_ai)
            if outcome == "verified":
                verified += 1
                findings.append(cast(str, hypothesis["id"]))
            elif outcome == "rejected":
                rejected += 1
            else:
                stalled += 1
        result: dict[str, object] = {"hypotheses_new": new, "verified": verified, "rejected": rejected, "stale": stalled, "findings": findings}
        if ai_notes:
            result["ai_notes"] = ai_notes
        return result

    def _budget_for(self, run_id: UUID) -> BudgetContext:
        with connection(self.database_path) as db:
            run = db.execute("SELECT target_id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
            cap = 0.50
            if run is not None:
                target = db.execute("SELECT budget_cap_usd FROM targets WHERE id = ?", (run["target_id"],)).fetchone()
                if target is not None:
                    cap = float(target["budget_cap_usd"])
            spent = db.execute("SELECT COALESCE(SUM(usd), 0) AS total FROM cost_ledger WHERE run_id = ?", (str(run_id),)).fetchone()
        return BudgetContext(run_budget_usd=cap, spent_usd=float(spent["total"]) if spent else 0.0)

    def _ai_analyst(
        self, run_id: UUID, fresh: tuple[EvidenceView, ...], signals: tuple[SignalView, ...], budget: BudgetContext
    ) -> tuple[list[tuple[HypothesisDraft, str]], str]:
        """Model-backed hypotheses. Invalid drafts are dropped; never trusted blindly."""
        gateway = self.gateway
        if gateway is None or not gateway.config.configured:
            return [], "ai analyst skipped: no provider configured"
        if not budget.can_spend(0):
            self._audit(run_id, "ai_skipped_budget", {"role": "analyst"})
            return [], "ai analyst skipped: run budget exhausted"
        items = [
            {"id": str(view.id), "module": view.module, "param": view.param, "endpoint": view.endpoint_url,
             "signals": list(view.signals), "markers": list(view.markers), "timing_anomaly": view.timing_anomaly,
             "xss_context": view.xss_context, "probe_kind": view.probe_kind}
            for view in fresh[:MAX_AI_EVIDENCE_ITEMS]
        ]
        prompt = (
            "Observed web-security test evidence (JSON). Propose hypotheses ONLY for evidence shown. "
            f"Allowed classes: {sorted(ALLOWED_CLASSES)}. Evidence: {json.dumps(items)} "
            f"Scanner signals: {json.dumps([{'endpoint': s.endpoint_url, 'template': s.template_id, 'name': s.name} for s in signals])}. "
            "Respond with a single JSON object."
        )
        try:
            result = gateway.generate(
                AIRole.ANALYST, prompt,
                {"required": ["hypotheses"]}, budget, run_id=run_id,
            )
        except (ProviderError, RuntimeError) as error:
            return [], f"ai analyst failed, deterministic baseline kept: {type(error).__name__}"
        return self._validate_drafts(result, fresh)

    def _validate_drafts(self, result: dict[str, object], fresh: tuple[EvidenceView, ...]) -> tuple[list[tuple[HypothesisDraft, str]], str]:
        output = result.get("output")
        model = str(result.get("model", "unknown"))
        if not isinstance(output, dict):
            return [], "ai analyst output unreadable; deterministic baseline kept"
        raw = output.get("hypotheses", [])
        if not isinstance(raw, list):
            return [], "ai analyst output malformed; deterministic baseline kept"
        fresh_ids = {view.id for view in fresh}
        valid: list[tuple[HypothesisDraft, str]] = []
        dropped = 0
        for item in raw:
            if not isinstance(item, dict):
                dropped += 1
                continue
            try:
                vuln_class = str(item["vuln_class"])
                endpoint = str(item["endpoint_url"])
                rationale = str(item["rationale"])
                confidence = min(1.0, max(0.0, float(item.get("confidence", 0.4))))
                cited = tuple(UUID(identity) for identity in item.get("evidence_ids", []))
            except (KeyError, ValueError, TypeError, AttributeError):
                dropped += 1
                continue
            if vuln_class not in ALLOWED_CLASSES or not endpoint or not rationale or not set(cited) <= fresh_ids:
                dropped += 1
                continue
            valid.append((HypothesisDraft(endpoint_url=endpoint, vuln_class=vuln_class, rationale=f"AI: {rationale}", confidence=confidence, evidence_ids=cited), model))
        return valid, f"ai analyst: {len(valid)} accepted, {dropped} dropped (model {model})"

    async def _settle(self, run_id: UUID, target_id: UUID, hypothesis: dict[str, object], use_ai: bool = False) -> str:
        hypothesis_id = UUID(str(hypothesis["id"]))
        vuln_class = str(hypothesis["vuln_class"])
        followups = cast(int, hypothesis["followups"])
        oob_hits = self._oob_hits()
        while True:
            views = self._views_for(hypothesis_id)
            sqlmap_params = tuple(param for view in views for param in view.sqlmap_params)
            verdict, voter = self._verify(run_id, hypothesis, vuln_class, views, sqlmap_params, oob_hits, use_ai)
            self._insert_verification(hypothesis_id, verdict.vote, verdict.reason, [view.id for view in views], voter=voter)
            if verdict.vote is VerificationVote.CONFIRM:
                self._insert_finding(run_id, target_id, hypothesis_id, verdict, hypothesis, views)
                self._set_status(hypothesis_id, HypothesisStatus.VERIFIED)
                return "verified"
            if verdict.vote is VerificationVote.REJECT or followups >= MAX_FOLLOWUPS:
                self._set_status(hypothesis_id, HypothesisStatus.REJECTED if verdict.vote is VerificationVote.REJECT else HypothesisStatus.STALE)
                return "rejected" if verdict.vote is VerificationVote.REJECT else "stale"
            followups += 1
            await self._followup(run_id, hypothesis, views)
            self._set_followups(hypothesis_id, followups)

    def _verify(
        self,
        run_id: UUID,
        hypothesis: dict[str, object],
        vuln_class: str,
        views: tuple[EvidenceView, ...],
        sqlmap_params: tuple[str, ...],
        oob_hits: tuple[str, ...],
        use_ai: bool,
    ) -> tuple[Verdict, str]:
        """Model vote first when opted in; deterministic fallback on any doubt."""
        if use_ai and self.gateway is not None and self.gateway.config.configured:
            budget = self._budget_for(run_id)
            if not budget.can_spend(0):
                self._audit(run_id, "ai_skipped_budget", {"role": "verifier"})
            else:
                author = str(hypothesis.get("author") or "")
                author_model = author if author != "deterministic" else None
                model_verdict = self._ai_verify(run_id, hypothesis, vuln_class, views, budget, author_model)
                if model_verdict is not None:
                    return model_verdict
        return verify_hypothesis(vuln_class, views, sqlmap_params, oob_hits), "deterministic"

    def _ai_verify(
        self,
        run_id: UUID,
        hypothesis: dict[str, object],
        vuln_class: str,
        views: tuple[EvidenceView, ...],
        budget: BudgetContext,
        author_model: str | None,
    ) -> tuple[Verdict, str] | None:
        gateway = self.gateway
        if gateway is None:
            return None
        linked = {view.id for view in views}
        items = [
            {"id": str(view.id), "kind": view.kind, "module": view.module, "param": view.param,
             "signals": list(view.signals), "markers": list(view.markers), "timing_anomaly": view.timing_anomaly,
             "xss_context": view.xss_context, "probe_kind": view.probe_kind, "status_changed": view.status_changed,
             "length_delta": view.length_delta, "sqlmap": list(view.sqlmap_params)}
            for view in views[:MAX_AI_EVIDENCE_ITEMS]
        ]
        prompt = (
            f"Hypothesis: {vuln_class} at {hypothesis['endpoint_url']}. Rationale: {hypothesis.get('rationale', '')}. "
            f"Linked evidence (JSON): {json.dumps(items)}. "
            "Vote CONFIRM only if the evidence reproducibly demonstrates the vulnerability, "
            "REJECT if it refutes it, else UNCERTAIN. Cite only the evidence IDs shown. Respond with a single JSON object."
        )
        try:
            result = gateway.generate(
                AIRole.VERIFIER, prompt,
                {"required": ["vote", "reason", "evidence_ids"]}, budget, run_id=run_id, author_model=author_model,
            )
        except (ProviderError, RuntimeError):
            return None
        output = result.get("output")
        model = str(result.get("model", "unknown"))
        if not isinstance(output, dict):
            return None
        try:
            vote = VerificationVote(str(output["vote"]).lower())
            reason = str(output["reason"])
            cited = tuple(UUID(identity) for identity in output.get("evidence_ids", []))
        except (KeyError, ValueError, TypeError, AttributeError):
            return None
        if not reason or not set(cited) <= linked:
            return None
        return Verdict(vote=vote, reason=f"AI: {reason}", confidence=0.7 if vote is VerificationVote.CONFIRM else 0.4), model

    def _audit(self, run_id: UUID, event: str, detail: dict[str, object]) -> None:
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), "system", event, json_value({"run_id": str(run_id), **detail})),
            )

    async def _followup(self, run_id: UUID, hypothesis: dict[str, object], views: tuple[EvidenceView, ...]) -> None:
        from app.testing.modules.api import api_probes
        from app.testing.modules.idor import sequential_probes

        vuln_class = str(hypothesis["vuln_class"])
        param = next((view.param for view in views if view.param), "")
        endpoint = str(hypothesis["endpoint_url"])
        if vuln_class == "sqli":
            probes = sqli_probes(param)
        elif vuln_class == "xss":
            probes = xss_probes(param)
        elif vuln_class == "idor":
            probes = sequential_probes(param)
        elif vuln_class == "api":
            probes = api_probes(endpoint, param)
        else:
            return  # ssrf waits on callbacks; re-probing adds no signal
        if not probes:
            return
        await self.testing.run_plan(run_id, [ProbePlan(url=endpoint, param=param, probes=probes)], max_probes=len(probes))
        new_ids = [view.id for view in self._views_for(UUID(str(hypothesis["id"]))) if view.id not in {view.id for view in views}]
        if new_ids:
            self._append_evidence(UUID(str(hypothesis["id"])), new_ids)

    def _oob_hits(self) -> tuple[str, ...]:
        with connection(self.database_path) as db:
            rows = db.execute("SELECT DISTINCT token FROM oob_callbacks").fetchall()
        return tuple(str(row["token"]) for row in rows)

    def _views_for(self, hypothesis_id: UUID) -> tuple[EvidenceView, ...]:
        with connection(self.database_path) as db:
            row = db.execute("SELECT evidence_ids FROM hypotheses WHERE id = ?", (str(hypothesis_id),)).fetchone()
            if row is None:
                return ()
            wanted = {UUID(identity) for identity in json.loads(row["evidence_ids"])}
        return tuple(view for view in self._load_evidence_by_ids(wanted) if view.id in wanted)

    def _load_evidence(self, run_id: UUID) -> tuple[EvidenceView, ...]:
        with connection(self.database_path) as db:
            rows = db.execute(
                "SELECT e.id, e.kind, e.analysis, t.type, t.payload FROM evidence e "
                "JOIN test_actions t ON e.test_action_id = t.id WHERE t.run_id = ? ORDER BY e.created_at",
                (str(run_id),),
            ).fetchall()
        return tuple(self._to_view(row["id"], row["kind"], row["type"], json.loads(row["analysis"]), json.loads(row["payload"])) for row in rows)

    def _load_evidence_by_ids(self, wanted: set[UUID]) -> tuple[EvidenceView, ...]:
        if not wanted:
            return ()
        placeholders = ",".join("?" for _ in wanted)
        with connection(self.database_path) as db:
            rows = db.execute(
                f"SELECT e.id, e.kind, e.analysis, t.type, t.payload FROM evidence e "
                f"JOIN test_actions t ON e.test_action_id = t.id WHERE e.id IN ({placeholders})",
                tuple(str(identity) for identity in wanted),
            ).fetchall()
        return tuple(self._to_view(row["id"], row["kind"], row["type"], json.loads(row["analysis"]), json.loads(row["payload"])) for row in rows)

    @staticmethod
    def _to_view(identity: str, kind: str, module: str, analysis: dict[str, object], payload: dict[str, object]) -> EvidenceView:
        from urllib.parse import urlparse

        param = str(payload.get("param", ""))
        probe_kind = str(payload.get("kind", ""))
        endpoint = str(payload.get("url", ""))
        signals: tuple[str, ...] = ()
        markers: tuple[str, ...] = ()
        timing = False
        context = None
        sqlmap: tuple[str, ...] = ()
        token = None
        status_changed = False
        length_delta = 0
        if kind == "diff":
            mutated = analysis.get("mutated")
            baseline = analysis.get("baseline")
            if isinstance(mutated, dict) and isinstance(baseline, dict):
                endpoint = str(mutated.get("url") or baseline.get("url") or endpoint)
            raw_signals = analysis.get("signals", [])
            if isinstance(raw_signals, list):
                signals = tuple(str(item) for item in raw_signals)
            diff = analysis.get("diff")
            if isinstance(diff, dict):
                raw_markers = diff.get("markers", [])
                if isinstance(raw_markers, list):
                    markers = tuple(str(item) for item in raw_markers)
                timing = bool(diff.get("timing_anomaly", False))
                status_changed = bool(diff.get("status_changed", False))
                try:
                    length_delta = int(diff.get("length_delta", 0))
                except (TypeError, ValueError):
                    length_delta = 0
            if module == "ssrf":
                token = urlparse(str(payload.get("payload", ""))).path.rsplit("/", 1)[-1] or None
        elif kind == "analysis":
            raw_context = analysis.get("xss_context")
            context = str(raw_context) if raw_context is not None else None
        elif kind == "tool_output":
            entries = analysis.get("sqlmap", [])
            if isinstance(entries, list):
                sqlmap = tuple(str(entry["parameter"]) for entry in entries if isinstance(entry, dict))
        return EvidenceView(
            id=UUID(identity), kind=kind, module=module, param=param, endpoint_url=endpoint,
            signals=signals, markers=markers, timing_anomaly=timing, xss_context=context, sqlmap_params=sqlmap,
            probe_kind=probe_kind, ssrf_token=token, status_changed=status_changed, length_delta=length_delta,
        )

    def _load_signals(self, run_id: UUID) -> tuple[SignalView, ...]:
        with connection(self.database_path) as db:
            rows = db.execute("SELECT endpoint_url, template_id, name, severity_hint FROM signals WHERE run_id = ?", (str(run_id),)).fetchall()
        return tuple(SignalView(endpoint_url=row["endpoint_url"], template_id=row["template_id"], name=row["name"], severity=row["severity_hint"]) for row in rows)

    def _cited_evidence(self, run_id: UUID) -> set[UUID]:
        with connection(self.database_path) as db:
            rows = db.execute("SELECT evidence_ids FROM hypotheses WHERE run_id = ?", (str(run_id),)).fetchall()
        cited: set[UUID] = set()
        for row in rows:
            cited.update(UUID(identity) for identity in json.loads(row["evidence_ids"]))
        return cited

    def _open_exists(self, run_id: UUID, endpoint: str, vuln_class: str) -> bool:
        with connection(self.database_path) as db:
            row = db.execute(
                "SELECT id FROM hypotheses WHERE run_id = ? AND endpoint_url = ? AND vuln_class = ? AND status = 'open'",
                (str(run_id), endpoint, vuln_class),
            ).fetchone()
        return row is not None

    def _insert_hypothesis(self, run_id: UUID, target_id: UUID, draft: HypothesisDraft, author: str = "deterministic") -> UUID:
        hypothesis_id = uuid4()
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO hypotheses (id, run_id, target_id, endpoint_url, vuln_class, rationale, confidence, author, prompt_version, status, evidence_ids, followups, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 0, ?)",
                (str(hypothesis_id), str(run_id), str(target_id), draft.endpoint_url, draft.vuln_class, draft.rationale, draft.confidence, author, ANALYST_VERSION, json_value([str(identity) for identity in draft.evidence_ids]), now),
            )
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (now, "system", "hypothesis_raised", json_value({"run_id": str(run_id), "hypothesis_id": str(hypothesis_id), "class": draft.vuln_class, "author": author})))
        return hypothesis_id

    def _open_hypotheses(self, run_id: UUID) -> list[dict[str, object]]:
        with connection(self.database_path) as db:
            rows = db.execute("SELECT id, endpoint_url, vuln_class, rationale, confidence, followups, author FROM hypotheses WHERE run_id = ? AND status = 'open'", (str(run_id),)).fetchall()
        return [dict(row) for row in rows]

    def _insert_verification(self, hypothesis_id: UUID, vote: VerificationVote, reason: str, evidence_ids: list[UUID], voter: str = "deterministic") -> UUID:
        verification_id = uuid4()
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(verification_id), str(hypothesis_id), voter, vote.value, reason, json_value([str(identity) for identity in evidence_ids]), now),
            )
        return verification_id

    def _insert_finding(self, run_id: UUID, target_id: UUID, hypothesis_id: UUID, verdict: Verdict, hypothesis: dict[str, object], views: tuple[EvidenceView, ...]) -> UUID:
        meta = CLASS_META.get(str(hypothesis["vuln_class"]), {"severity": "low", "impact": "", "remediation": ""})
        with connection(self.database_path) as db:
            verification = db.execute("SELECT id FROM verifications WHERE hypothesis_id = ? ORDER BY created_at DESC LIMIT 1", (str(hypothesis_id),)).fetchone()
            assert verification is not None
            placeholders = ",".join("?" for _ in views) or "''"
            payload_rows = db.execute(
                f"SELECT t.payload FROM evidence e JOIN test_actions t ON e.test_action_id = t.id WHERE e.id IN ({placeholders})",
                tuple(str(view.id) for view in views),
            ).fetchall() if views else []
            repro_probes = sorted({f"{json.loads(row['payload']).get('param', '')}={json.loads(row['payload']).get('payload', '')}" for row in payload_rows})
            finding_id = uuid4()
            db.execute(
                "INSERT INTO findings (id, run_id, target_id, hypothesis_id, verification_id, title, severity, endpoint_url, description, repro, impact, remediation, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(finding_id), str(run_id), str(target_id), str(hypothesis_id), verification["id"],
                    f"{str(hypothesis['vuln_class']).upper()} on {hypothesis['endpoint_url']}", str(meta["severity"]),
                    str(hypothesis["endpoint_url"]), f"{hypothesis['rationale']} Verifier: {verdict.reason}",
                    json_value({"endpoint": hypothesis["endpoint_url"], "probes": repro_probes}),
                    str(meta["impact"]), str(meta["remediation"]), verdict.confidence, datetime.now(UTC).isoformat(),
                ),
            )
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (datetime.now(UTC).isoformat(), "system", "finding_confirmed", json_value({"run_id": str(run_id), "finding_id": str(finding_id)})))
        return finding_id

    def _set_status(self, hypothesis_id: UUID, status: HypothesisStatus) -> None:
        with connection(self.database_path) as db:
            db.execute("UPDATE hypotheses SET status = ? WHERE id = ?", (status.value, str(hypothesis_id)))

    def _set_followups(self, hypothesis_id: UUID, followups: int) -> None:
        with connection(self.database_path) as db:
            db.execute("UPDATE hypotheses SET followups = ? WHERE id = ?", (followups, str(hypothesis_id)))

    def _append_evidence(self, hypothesis_id: UUID, new_ids: list[UUID]) -> None:
        with connection(self.database_path) as db:
            row = db.execute("SELECT evidence_ids FROM hypotheses WHERE id = ?", (str(hypothesis_id),)).fetchone()
            current = [UUID(identity) for identity in json.loads(row["evidence_ids"])] if row else []
            merged = current + [identity for identity in new_ids if identity not in current]
            db.execute("UPDATE hypotheses SET evidence_ids = ? WHERE id = ?", (json_value([str(identity) for identity in merged]), str(hypothesis_id)))

    def _run_target(self, run_id: UUID) -> UUID:
        with connection(self.database_path) as db:
            row = db.execute("SELECT target_id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
        if row is None:
            raise LookupError("Run does not exist.")
        return UUID(row["target_id"])

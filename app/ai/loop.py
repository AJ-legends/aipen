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
}


class LoopService:
    __test__ = False  # not a pytest test class despite the name

    def __init__(self, database_path: Path, artifacts_dir: Path, testing: TestingService | None = None) -> None:
        self.database_path = database_path
        self.testing = testing or TestingService(database_path, artifacts_dir)

    async def analyze_run(self, run_id: UUID) -> dict[str, object]:
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
        verified = rejected = stalled = 0
        findings: list[str] = []
        for hypothesis in self._open_hypotheses(run_id):
            outcome = await self._settle(run_id, target_id, hypothesis)
            if outcome == "verified":
                verified += 1
                findings.append(cast(str, hypothesis["id"]))
            elif outcome == "rejected":
                rejected += 1
            else:
                stalled += 1
        return {"hypotheses_new": new, "verified": verified, "rejected": rejected, "stale": stalled, "findings": findings}

    async def _settle(self, run_id: UUID, target_id: UUID, hypothesis: dict[str, object]) -> str:
        hypothesis_id = UUID(str(hypothesis["id"]))
        vuln_class = str(hypothesis["vuln_class"])
        followups = cast(int, hypothesis["followups"])
        while True:
            views = self._views_for(hypothesis_id)
            sqlmap_params = tuple(param for view in views for param in view.sqlmap_params)
            verdict = verify_hypothesis(vuln_class, views, sqlmap_params)
            self._insert_verification(hypothesis_id, verdict.vote, verdict.reason, [view.id for view in views])
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

    async def _followup(self, run_id: UUID, hypothesis: dict[str, object], views: tuple[EvidenceView, ...]) -> None:
        vuln_class = str(hypothesis["vuln_class"])
        param = next((view.param for view in views if view.param), "")
        probes = sqli_probes(param) if vuln_class == "sqli" else xss_probes(param)
        if not probes:
            return
        await self.testing.run_plan(run_id, [ProbePlan(url=str(hypothesis["endpoint_url"]), param=param, probes=probes)], max_probes=len(probes))
        new_ids = [view.id for view in self._views_for(UUID(str(hypothesis["id"]))) if view.id not in {view.id for view in views}]
        if new_ids:
            self._append_evidence(UUID(str(hypothesis["id"])), new_ids)

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
        param = str(payload.get("param", ""))
        endpoint = str(payload.get("url", ""))
        signals: tuple[str, ...] = ()
        markers: tuple[str, ...] = ()
        timing = False
        context = None
        sqlmap: tuple[str, ...] = ()
        if kind == "diff":
            mutated = analysis.get("mutated")
            baseline = analysis.get("baseline")
            assert isinstance(mutated, dict) and isinstance(baseline, dict)
            endpoint = str(mutated.get("url") or baseline.get("url") or endpoint)
            raw_signals = analysis.get("signals", [])
            assert isinstance(raw_signals, list)
            signals = tuple(str(item) for item in raw_signals)
            diff = analysis.get("diff")
            assert isinstance(diff, dict)
            raw_markers = diff.get("markers", [])
            assert isinstance(raw_markers, list)
            markers = tuple(str(item) for item in raw_markers)
            timing = bool(diff.get("timing_anomaly", False))
        elif kind == "analysis":
            raw_context = analysis.get("xss_context")
            context = str(raw_context) if raw_context is not None else None
        elif kind == "tool_output":
            entries = analysis.get("sqlmap", [])
            assert isinstance(entries, list)
            sqlmap = tuple(str(entry["parameter"]) for entry in entries if isinstance(entry, dict))
        return EvidenceView(
            id=UUID(identity), kind=kind, module=module, param=param, endpoint_url=endpoint,
            signals=signals, markers=markers, timing_anomaly=timing, xss_context=context, sqlmap_params=sqlmap,
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

    def _insert_hypothesis(self, run_id: UUID, target_id: UUID, draft: HypothesisDraft) -> UUID:
        hypothesis_id = uuid4()
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO hypotheses (id, run_id, target_id, endpoint_url, vuln_class, rationale, confidence, author, prompt_version, status, evidence_ids, followups, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, 0, ?)",
                (str(hypothesis_id), str(run_id), str(target_id), draft.endpoint_url, draft.vuln_class, draft.rationale, draft.confidence, "deterministic", ANALYST_VERSION, json_value([str(identity) for identity in draft.evidence_ids]), now),
            )
            db.execute("INSERT INTO audit_log (ts, actor, event, detail) VALUES (?, ?, ?, ?)", (now, "system", "hypothesis_raised", json_value({"run_id": str(run_id), "hypothesis_id": str(hypothesis_id), "class": draft.vuln_class})))
        return hypothesis_id

    def _open_hypotheses(self, run_id: UUID) -> list[dict[str, object]]:
        with connection(self.database_path) as db:
            rows = db.execute("SELECT id, endpoint_url, vuln_class, rationale, confidence, followups FROM hypotheses WHERE run_id = ? AND status = 'open'", (str(run_id),)).fetchall()
        return [dict(row) for row in rows]

    def _insert_verification(self, hypothesis_id: UUID, vote: VerificationVote, reason: str, evidence_ids: list[UUID]) -> UUID:
        verification_id = uuid4()
        now = datetime.now(UTC).isoformat()
        with connection(self.database_path) as db:
            db.execute(
                "INSERT INTO verifications (id, hypothesis_id, voter, vote, reason, evidence_ids, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(verification_id), str(hypothesis_id), "deterministic", vote.value, reason, json_value([str(identity) for identity in evidence_ids]), now),
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

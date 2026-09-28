"""Deterministic verifier: hypothesis + cited evidence -> vote.

Votes CONFIRM only on reproducible cited evidence. UNCERTAIN triggers at most
two follow-up test rounds (enforced by the loop); anything else is REJECT.
"""
from dataclasses import dataclass

from app.ai.analyst import EvidenceView
from app.core.schemas import VerificationVote


@dataclass(frozen=True, slots=True)
class Verdict:
    vote: VerificationVote
    reason: str
    confidence: float


def verify_hypothesis(
    vuln_class: str,
    evidence: tuple[EvidenceView, ...],
    sqlmap_confirmed_params: tuple[str, ...] = (),
    oob_hits: tuple[str, ...] = (),
) -> Verdict:
    cited = [item.id for item in evidence]
    cite = f" (evidence: {', '.join(str(identity) for identity in cited)})" if cited else " (no cited evidence)"
    if not evidence:
        return Verdict(VerificationVote.REJECT, f"No evidence linked to this hypothesis{cite}", 0.0)
    if vuln_class == "sqli":
        if sqlmap_confirmed_params:
            return Verdict(VerificationVote.CONFIRM, f"sqlmap confirmed injection on {sorted(sqlmap_confirmed_params)}{cite}", 0.95)
        if any(item.markers for item in evidence):
            return Verdict(VerificationVote.CONFIRM, f"DB error markers reproduced on {[item.param for item in evidence if item.markers]}{cite}", 0.8)
        if any(item.timing_anomaly for item in evidence):
            return Verdict(VerificationVote.UNCERTAIN, f"Timing anomaly without error markers needs a discriminating retest{cite}", 0.45)
        return Verdict(VerificationVote.REJECT, f"No markers or timing anomaly in linked evidence{cite}", 0.2)
    if vuln_class == "xss":
        contexts = {item.xss_context for item in evidence if item.xss_context}
        if contexts & {"raw", "attribute", "js-string"}:
            ordered = sorted(contexts & {"raw", "attribute", "js-string"})
            return Verdict(VerificationVote.CONFIRM, f"Canary reflected unencoded in {ordered} context{cite}", 0.8)
        if contexts == {"encoded"}:
            return Verdict(VerificationVote.REJECT, f"Canary reflected only encoded; output is neutralised{cite}", 0.2)
        return Verdict(VerificationVote.UNCERTAIN, f"Reflection observed without a classifiable context{cite}", 0.4)
    if vuln_class == "idor":
        cross = [item.param for item in evidence if item.probe_kind == "cross-account" and (item.status_changed or abs(item.length_delta) >= 50)]
        if cross:
            return Verdict(VerificationVote.CONFIRM, f"Cross-account IDOR: {sorted(set(cross))} returns foreign data{cite}", 0.85)
        if any(item.status_changed or abs(item.length_delta) >= 50 for item in evidence):
            return Verdict(VerificationVote.CONFIRM, f"Neighbor-ID responses differ; object reference not enforced{cite}", 0.7)
        return Verdict(VerificationVote.REJECT, f"Neighbor IDs return identical responses{cite}", 0.25)
    if vuln_class == "ssrf":
        hit = sorted({item.ssrf_token for item in evidence if item.ssrf_token and item.ssrf_token in oob_hits})
        if hit:
            return Verdict(VerificationVote.CONFIRM, f"OOB callback received for canary {hit}{cite}", 0.9)
        return Verdict(VerificationVote.UNCERTAIN, f"Canary sent but no callback observed yet{cite}", 0.3)
    if vuln_class == "api":
        if any(item.markers for item in evidence):
            return Verdict(VerificationVote.CONFIRM, f"Verbose error leakage reproduced{cite}", 0.6)
        if any(item.status_changed or abs(item.length_delta) >= 50 for item in evidence):
            return Verdict(VerificationVote.CONFIRM, f"API object responses differ across subjects{cite}", 0.6)
        return Verdict(VerificationVote.REJECT, f"API responses identical; no leakage observed{cite}", 0.25)
    return Verdict(VerificationVote.REJECT, f"Unsupported vulnerability class '{vuln_class}'{cite}", 0.0)

"""Deterministic analyst: evidence + signals -> hypothesis drafts.

Pure rules; model-backed authors plug in later behind the same draft contract.
A draft never claims a finding — only the verifier can confirm one.
"""
from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True, slots=True)
class EvidenceView:
    id: UUID
    kind: str
    module: str
    param: str
    endpoint_url: str
    signals: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    timing_anomaly: bool = False
    xss_context: str | None = None
    sqlmap_params: tuple[str, ...] = ()
    probe_kind: str = ""
    ssrf_token: str | None = None
    status_changed: bool = False
    length_delta: int = 0


@dataclass(frozen=True, slots=True)
class SignalView:
    endpoint_url: str
    template_id: str | None
    name: str
    severity: str | None


@dataclass(frozen=True, slots=True)
class HypothesisDraft:
    endpoint_url: str
    vuln_class: str
    rationale: str
    confidence: float
    evidence_ids: tuple[UUID, ...] = ()
    signal_names: tuple[str, ...] = field(default_factory=tuple)


_SIGNAL_CLASS = {
    "sqli-error-based": "sqli",
    "sqli-blind": "sqli",
    "sqli-time-based": "sqli",
    "xss-reflected": "xss",
    "xss-stored": "xss",
}


def _signal_class(template_id: str | None, name: str) -> str | None:
    if template_id and template_id in _SIGNAL_CLASS:
        return _SIGNAL_CLASS[template_id]
    lowered = name.lower()
    if "sql injection" in lowered or "sqli" in lowered:
        return "sqli"
    if "xss" in lowered or "cross-site" in lowered:
        return "xss"
    return None


def analyze_evidence(evidence: tuple[EvidenceView, ...], signals: tuple[SignalView, ...]) -> list[HypothesisDraft]:
    """Group observed signals by (endpoint, class) into hypothesis drafts."""

    @dataclass(slots=True)
    class _Group:
        rationales: list[str] = field(default_factory=list)
        confidence: float = 0.0
        evidence: list[UUID] = field(default_factory=list)
        signals: list[str] = field(default_factory=list)

    groups: dict[tuple[str, str], _Group] = {}

    def _add(endpoint: str, vuln_class: str, rationale: str, confidence: float, evidence_id: UUID | None, signal: str | None) -> None:
        slot = groups.setdefault((endpoint, vuln_class), _Group())
        slot.rationales.append(rationale)
        slot.confidence = max(slot.confidence, confidence)
        if evidence_id is not None:
            slot.evidence.append(evidence_id)
        if signal is not None:
            slot.signals.append(signal)

    for item in evidence:
        if item.module == "sqli" and item.markers:
            _add(item.endpoint_url, "sqli", f"DB error markers {sorted(item.markers)} on param '{item.param}'", 0.7, item.id, None)
        elif item.module == "sqli" and item.timing_anomaly:
            _add(item.endpoint_url, "sqli", f"Time anomaly on param '{item.param}' without error markers", 0.5, item.id, None)
        elif item.module == "xss" and item.xss_context in ("raw", "attribute", "js-string"):
            _add(item.endpoint_url, "xss", f"Canary reflected in {item.xss_context} context on param '{item.param}'", 0.6 if item.xss_context == "raw" else 0.5, item.id, None)
        elif item.module == "xss" and item.xss_context == "encoded":
            continue  # properly encoded: no hypothesis
        elif item.module == "idor" and (item.status_changed or abs(item.length_delta) >= 50):
            confidence = 0.65 if item.probe_kind == "cross-account" else 0.5
            _add(item.endpoint_url, "idor", f"Neighbor-ID response differs ({item.probe_kind}) on param '{item.param}'", confidence, item.id, None)
        elif item.module == "ssrf" and item.ssrf_token:
            _add(item.endpoint_url, "ssrf", f"OOB canary sent for param '{item.param}'; awaiting callback", 0.3, item.id, None)
        elif item.module == "api" and item.markers:
            _add(item.endpoint_url, "api", f"Verbose error markers {sorted(item.markers)} on param '{item.param}'", 0.55, item.id, None)
        elif item.module == "api" and (item.status_changed or abs(item.length_delta) >= 50):
            _add(item.endpoint_url, "api", f"API response differs ({item.probe_kind}) on param '{item.param}'", 0.5, item.id, None)
    for signal in signals:
        vuln_class = _signal_class(signal.template_id, signal.name)
        if vuln_class is None:
            continue
        _add(signal.endpoint_url, vuln_class, f"Scanner signal '{signal.name}' ({signal.template_id or 'unknown'})", 0.4, None, signal.name)

    drafts: list[HypothesisDraft] = []
    for (endpoint, vuln_class), slot in groups.items():
        drafts.append(
            HypothesisDraft(
                endpoint_url=endpoint,
                vuln_class=vuln_class,
                rationale="; ".join(slot.rationales),
                confidence=slot.confidence,
                evidence_ids=tuple(slot.evidence),
                signal_names=tuple(slot.signals),
            )
        )
    return drafts

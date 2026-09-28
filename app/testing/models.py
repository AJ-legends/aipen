"""Domain models for differential test execution. No I/O here."""
from dataclasses import dataclass, field

from pydantic import BaseModel, Field


class Probe(BaseModel):
    """A single mutation to try against one parameter."""

    module: str = Field(description="Originating module: sqli | xss | idor | ssrf | api")
    kind: str = Field(description="Probe kind, e.g. error-based, idor-sequential, ssrf-canary")
    param: str
    payload: str
    risk_tier: str = "low"
    session: str | None = Field(default=None, description="Named target session for the mutated request")
    strip_auth: bool = Field(default=False, description="Send the mutated request without session headers")


class ProbePlan(BaseModel):
    """One endpoint × parameter with all probes to run."""

    url: str
    method: str = "GET"
    param: str
    baseline_value: str = ""
    probes: list[Probe] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CapturedResponse:
    url: str
    status_code: int
    length: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float


@dataclass(frozen=True, slots=True)
class ResponseDiff:
    status_changed: bool
    length_delta: int
    markers: tuple[str, ...] = ()
    timing_ms: float = 0.0
    timing_anomaly: bool = False


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    probe: Probe
    baseline: CapturedResponse
    mutated: CapturedResponse
    diff: ResponseDiff
    signals: tuple[str, ...] = field(default_factory=tuple)

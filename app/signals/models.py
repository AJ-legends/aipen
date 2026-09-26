"""Signal record model. Signals seed hypotheses; never become findings directly."""
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SignalRecord:
    url: str
    template_id: str | None = None
    name: str = ""
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class SignalResult:
    signals: tuple[SignalRecord, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)

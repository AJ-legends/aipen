"""API vulnerability probes (GET-feasible only).

BOLA-by-query, verbose-error leakage, and unauthenticated access run as LOW
probes. Mass-assignment is detection-shaped and always HITL-gated: real
mass-assignment needs state-changing methods the policy engine denies.
"""
from app.testing.models import Probe
from app.testing.modules.idor import is_api_url, is_identifier_param, sequential_variants
from app.testing.risk import classify

MODULE = "api"

VERBOSE_ERROR_MARKERS: tuple[str, ...] = (
    "traceback (most recent call last)",
    "stack trace",
    "exception in",
    "at com.",
    "at java.",
    "at org.",
    ".php on line",
    "sqlstate",
    "undefined index",
    "nullpointerexception",
)

MASS_ASSIGNMENT_FIELDS: tuple[str, ...] = ("role", "is_admin", "isadmin", "admin", "privilege", "plan", "balance", "price")


def bola_probes(param: str, value: str = "") -> list[Probe]:
    return [
        Probe(module=MODULE, kind="bola-query", param=param, payload=variant, risk_tier=classify(MODULE, "bola-query").value)
        for variant in sequential_variants(value)
    ]


def verbose_error_probes(param: str, value: str = "") -> list[Probe]:
    return [
        Probe(module=MODULE, kind="verbose-errors", param=param, payload=value or "aipen", risk_tier=classify(MODULE, "verbose-errors").value)
    ]


def unauthenticated_probes(param: str, value: str = "") -> list[Probe]:
    return [
        Probe(module=MODULE, kind="unauthenticated", param=param, payload=value or "1", strip_auth=True, risk_tier=classify(MODULE, "unauthenticated").value)
    ]


def mass_assignment_probes(param: str) -> list[Probe]:
    """Query-shaped mass-assignment indicators. Always MEDIUM: needs operator eyes."""
    return [
        Probe(module=MODULE, kind="mass-assignment", param=field, payload="aipen-probe", risk_tier=classify(MODULE, "mass-assignment").value)
        for field in MASS_ASSIGNMENT_FIELDS
        if field != param
    ]


def api_probes(url: str, param: str, value: str = "", sessions: tuple[str, ...] = ()) -> list[Probe]:
    if not is_api_url(url):
        return []
    probes = [*verbose_error_probes(param, value)]
    if is_identifier_param(param):
        probes.extend(bola_probes(param, value))
    if sessions:
        probes.extend(unauthenticated_probes(param, value))
        probes.extend(mass_assignment_probes(param))
    return probes

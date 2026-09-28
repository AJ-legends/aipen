"""Static risk classification: (module, kind, method) -> tier. Pure and unit-tested."""
from app.core.schemas import RiskTier

# (module, kind-prefix) pairs that stay LOW on safe GET probes.
LOW_KINDS: tuple[tuple[str, str], ...] = (
    ("sqli", "error-based"),
    ("sqli", "time-based"),
    ("xss", "reflected"),
    ("idor", "sequential"),
    ("idor", "unauthenticated"),
    ("ssrf", "canary"),
    ("api", "bola-query"),
    ("api", "verbose-errors"),
    ("api", "unauthenticated"),
)

# Kinds that cross an auth boundary or change server-side state handling.
MEDIUM_KINDS: tuple[tuple[str, str], ...] = (
    ("idor", "cross-account"),
    ("api", "mass-assignment"),
)


def classify(module: str, kind: str, method: str = "GET") -> RiskTier:
    """Classify a probe. Non-GET methods and unknown modules are HIGH (approval-only)."""
    if method.upper() != "GET":
        return RiskTier.HIGH
    for mod, prefix in MEDIUM_KINDS:
        if module == mod and kind.startswith(prefix):
            return RiskTier.MEDIUM
    for mod, prefix in LOW_KINDS:
        if module == mod and kind.startswith(prefix):
            return RiskTier.LOW
    return RiskTier.HIGH

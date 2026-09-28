"""Curated IDOR/BOLA probe library. Single-session and cross-account variants."""
import re
from urllib.parse import urlparse

from app.testing.models import Probe
from app.testing.risk import classify

MODULE = "idor"

IDENTIFIER_HINTS: tuple[str, ...] = (
    "id", "user_id", "userid", "account_id", "customer_id", "member_id",
    "order_id", "profile_id", "post_id", "comment_id", "document_id",
    "file_id", "invoice_id", "payment_id", "uid", "owner_id", "group_id",
)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def is_identifier_param(name: str) -> bool:
    lowered = name.lower()
    return lowered in IDENTIFIER_HINTS or lowered.endswith(("_id", "id")) and len(lowered) <= 24


def is_api_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return "/api/" in path or path.startswith("/api")


def sequential_variants(value: str) -> list[str]:
    """Neighbor IDs for numeric values; nibble-flips for UUIDs."""
    if value.isdigit() and len(value) <= 10:
        number = int(value)
        return [str(number + 1), str(max(0, number - 1)), str(number + 10), "1"]
    if UUID_RE.match(value):
        flipped = value[:-1] + ("0" if value[-1] != "0" else "1")
        return [flipped, value[:-2] + ("00" if value[-2:] != "00" else "11")]
    return ["1", "2"]


def sequential_probes(param: str, value: str = "") -> list[Probe]:
    return [
        Probe(module=MODULE, kind="sequential", param=param, payload=variant, risk_tier=classify(MODULE, "sequential").value)
        for variant in sequential_variants(value)
    ]


def unauthenticated_probes(param: str, value: str = "") -> list[Probe]:
    """Same value, auth stripped: identical 200-with-data means missing auth."""
    return [
        Probe(module=MODULE, kind="unauthenticated", param=param, payload=value or "1", strip_auth=True, risk_tier=classify(MODULE, "unauthenticated").value)
    ]


def cross_account_probes(param: str, value: str, session: str) -> list[Probe]:
    """Replay another subject's IDs under the second session: always HITL-gated."""
    return [
        Probe(module=MODULE, kind="cross-account", param=param, payload=variant, session=session, risk_tier=classify(MODULE, "cross-account").value)
        for variant in sequential_variants(value)
    ]


def idor_probes(param: str, value: str = "", sessions: tuple[str, ...] = ()) -> list[Probe]:
    probes = [*sequential_probes(param, value)]
    if sessions:
        probes.extend(unauthenticated_probes(param, value))
        if len(sessions) >= 2:
            probes.extend(cross_account_probes(param, value or "1", sessions[1]))
    return probes

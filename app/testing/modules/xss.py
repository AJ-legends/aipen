"""Curated XSS probe library with reflection-context classification (pure)."""
from app.testing.models import Probe

MODULE = "xss"
CANARY = "aipenxss9"

REFLECTED_PAYLOADS: tuple[str, ...] = (
    CANARY,
    f"<{CANARY}>",
    f'"><svg onload="{CANARY}">',
    f"'><img src=x onerror={CANARY}>",
    f'";alert({CANARY})//',
)


def xss_probes(param: str) -> list[Probe]:
    return [Probe(module=MODULE, kind="reflected", param=param, payload=payload) for payload in REFLECTED_PAYLOADS]


def classify_context(body: str, marker: str = CANARY) -> str:
    """Classify how a marker is reflected. Pure; never executes anything."""
    if marker not in body:
        return "absent"
    idx = body.find(marker)
    tag_open = body.rfind("<", 0, idx)
    tag_close = body.rfind(">", 0, idx)
    if tag_open > tag_close:
        tag = body[tag_open:idx]
        if "=" in tag and (tag.count('"') % 2 == 1 or tag.count("'") % 2 == 1):
            return "attribute"
        return "raw"
    script_open = body.lower().rfind("<script", 0, idx)
    script_close = body.lower().rfind("</script", 0, idx)
    if script_open > script_close:
        return "js-string"
    window = body[max(0, idx - 120) : idx + len(marker) + 20]
    if any(entity in window for entity in ("&lt;", "&gt;", "&quot;", "&#")):
        return "encoded"
    return "raw"

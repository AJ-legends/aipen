"""Curated SSRF probe library. Out-of-band confirmation only; no callbacks, no finding."""
from urllib.parse import urlparse
from uuid import uuid4

from app.testing.models import Probe
from app.testing.risk import classify

MODULE = "ssrf"

URLISH_PARAMS: tuple[str, ...] = (
    "url", "redirect_url", "redirect", "next", "callback", "webhook", "webhook_url",
    "image_url", "avatar", "fetch", "uri", "link", "target", "dest", "destination",
    "feed", "logo", "picture", "file", "path",
)


def is_urlish_param(name: str) -> bool:
    return name.lower() in URLISH_PARAMS


def is_urlish_url(url: str) -> bool:
    lowered = urlparse(url).path.lower()
    return any(marker in lowered for marker in ("redirect", "callback", "webhook", "fetch", "proxy", "thumbnail", "preview"))


def canary_token() -> str:
    return uuid4().hex


def ssrf_probes(param: str, oob_base: str, token: str | None = None) -> list[Probe]:
    """One canary per param. Confirmation happens only via the OOB listener."""
    marker = token or canary_token()
    return [
        Probe(module=MODULE, kind="canary", param=param, payload=f"{oob_base.rstrip('/')}/{marker}", risk_tier=classify(MODULE, "canary").value)
    ]

"""Parsers for recorded Katana and ffuf output; no network or tool calls occur here."""
import json
from urllib.parse import parse_qs, urlparse

from app.discovery.models import DiscoveredEndpoint


def _endpoint(url: str, source: str, method: str = "GET", form_fields: tuple[str, ...] = ()) -> DiscoveredEndpoint:
    parsed = urlparse(url)
    parameters = tuple(sorted(parse_qs(parsed.query, keep_blank_values=True).keys()))
    normalized_url = parsed._replace(query="", fragment="").geturl()
    return DiscoveredEndpoint(
        url=normalized_url,
        method=method.upper(),
        parameters=parameters,
        form_fields=form_fields,
        is_api="/api/" in parsed.path or parsed.path.startswith("/api"),
        source=source,
    )


def parse_katana_jsonl(payload: bytes) -> tuple[DiscoveredEndpoint, ...]:
    endpoints: dict[tuple[str, str], DiscoveredEndpoint] = {}
    for line in payload.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        url = item.get("request", {}).get("endpoint") or item.get("url")
        if not isinstance(url, str):
            continue
        method = item.get("request", {}).get("method", "GET")
        if not isinstance(method, str):
            method = "GET"
        endpoint = _endpoint(url, "katana", method)
        endpoints[(endpoint.url, endpoint.method)] = endpoint
    return tuple(endpoints.values())


def parse_ffuf_json(payload: bytes) -> tuple[DiscoveredEndpoint, ...]:
    document = json.loads(payload.decode("utf-8", errors="replace"))
    endpoints: dict[tuple[str, str], DiscoveredEndpoint] = {}
    for item in document.get("results", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        endpoint = _endpoint(url, "ffuf")
        endpoints[(endpoint.url, endpoint.method)] = endpoint
    return tuple(endpoints.values())

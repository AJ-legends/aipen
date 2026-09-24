"""Deterministic recon summary. No network, tool, or AI calls."""
from urllib.parse import urlparse

from app.discovery.models import DiscoveredEndpoint
from app.recon.models import ApplicationProfile, HostRecord, HttpProbeRecord

AUTH_MARKERS = ("login", "auth", "token", "session", "oauth", "signin", "sso")
API_MARKERS = ("/api/", "/graphql", ".json", "/rest/", "/v1/", "/v2/", "/v3/")


def build_profile(
    hosts: tuple[HostRecord, ...],
    probes: tuple[HttpProbeRecord, ...],
    endpoints: tuple[DiscoveredEndpoint, ...],
) -> ApplicationProfile:
    tech: dict[str, None] = {}
    for probe in probes:
        if probe.webserver:
            tech[probe.webserver] = None
        for item in probe.technologies:
            tech[item] = None
    for host in hosts:
        for service in host.services:
            if service.product:
                label = service.product if not service.version else f"{service.product} {service.version}"
                tech[label] = None
            elif service.name:
                tech[service.name] = None

    params: dict[str, None] = {}
    forms: dict[str, None] = {}
    for endpoint in endpoints:
        for name in (*endpoint.parameters, *endpoint.form_fields):
            params[name] = None
        for name in endpoint.form_fields:
            forms[name] = None

    auth: dict[str, None] = {}
    api: dict[str, None] = {}
    for endpoint in endpoints:
        lowered = endpoint.url.lower()
        if any(marker in lowered for marker in AUTH_MARKERS):
            auth[endpoint.url] = None
        parsed_path = urlparse(endpoint.url).path.lower()
        if endpoint.is_api or any(marker in lowered or marker in parsed_path for marker in API_MARKERS):
            api[endpoint.url] = None
    for probe in probes:
        lowered = probe.url.lower()
        if any(marker in lowered for marker in API_MARKERS):
            api[probe.url] = None

    notes = f"{len(hosts)} host(s), {len(probes)} probe(s), {len(endpoints)} endpoint(s) summarised deterministically."
    return ApplicationProfile(
        tech_stack=tuple(tech.keys()),
        entry_points=tuple(params.keys()),
        auth_surfaces=tuple(auth.keys()),
        api_indicators=tuple(api.keys()),
        notes=notes,
    )

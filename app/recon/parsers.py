"""Strict parsers for saved tool output. Parsers never invoke a tool or make network calls."""
import json
from xml.etree import ElementTree

from app.recon.models import HostRecord, HttpProbeRecord, ServiceRecord


def parse_nmap_xml(payload: bytes) -> tuple[HostRecord, ...]:
    """Extract only live hosts and open services from Nmap XML output."""
    root = ElementTree.fromstring(payload)
    hosts: list[HostRecord] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = next((node.get("addr") for node in host.findall("address") if node.get("addrtype") in {"ipv4", "ipv6"}), None)
        if not address:
            continue
        hostname_node = host.find("hostnames/hostname")
        services: list[ServiceRecord] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            services.append(ServiceRecord(
                port=int(port.get("portid", "0")), protocol=port.get("protocol", "tcp"),
                name=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
                banner=service.get("extrainfo") if service is not None else None,
            ))
        hosts.append(HostRecord(ip=address, hostname=hostname_node.get("name") if hostname_node is not None else None, services=tuple(services)))
    return tuple(hosts)


def parse_httpx_jsonl(payload: bytes) -> tuple[HttpProbeRecord, ...]:
    probes: list[HttpProbeRecord] = []
    for line in payload.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        url = item.get("url") or item.get("input")
        if not isinstance(url, str):
            continue
        technologies = item.get("tech") or item.get("technologies") or []
        if not isinstance(technologies, list):
            technologies = []
        probes.append(HttpProbeRecord(url=url, status_code=item.get("status_code"), title=item.get("title"), webserver=item.get("webserver"), technologies=tuple(str(value) for value in technologies)))
    return tuple(probes)

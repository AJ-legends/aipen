from pathlib import Path

from app.recon.parsers import parse_httpx_jsonl, parse_nmap_xml

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_nmap_parser_keeps_only_open_services() -> None:
    hosts = parse_nmap_xml((FIXTURES / "nmap-sample.xml").read_bytes())
    assert len(hosts) == 1
    assert hosts[0].ip == "192.0.2.10"
    assert hosts[0].hostname == "app.example.test"
    assert [(service.port, service.name) for service in hosts[0].services] == [(443, "https")]


def test_httpx_parser_preserves_probe_metadata() -> None:
    probes = parse_httpx_jsonl((FIXTURES / "httpx-sample.jsonl").read_bytes())
    assert probes[0].status_code == 200
    assert probes[0].technologies == ("nginx", "FastAPI")
    assert probes[1].url.endswith("/api/status")

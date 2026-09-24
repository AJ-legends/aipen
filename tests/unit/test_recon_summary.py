from pathlib import Path

from app.discovery.parsers import parse_ffuf_json, parse_katana_jsonl
from app.recon.parsers import parse_httpx_jsonl, parse_nmap_xml
from app.recon.summary import build_profile

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_build_profile_extracts_tech_and_api() -> None:
    hosts = parse_nmap_xml((FIXTURES / "nmap-sample.xml").read_bytes())
    probes = parse_httpx_jsonl((FIXTURES / "httpx-sample.jsonl").read_bytes())
    endpoints = parse_katana_jsonl((FIXTURES / "katana-sample.jsonl").read_bytes())
    profile = build_profile(hosts, probes, endpoints)
    assert "nginx" in profile.tech_stack
    assert "FastAPI" in profile.tech_stack
    assert "category" in profile.entry_points
    assert any("/api/v1/items" in url for url in profile.api_indicators)


def test_build_profile_detects_auth_and_ffuf_api() -> None:
    hosts = parse_nmap_xml((FIXTURES / "nmap-sample.xml").read_bytes())
    endpoints = parse_ffuf_json((FIXTURES / "ffuf-sample.json").read_bytes())
    profile = build_profile(hosts, (), endpoints)
    assert any("/api/health" in url for url in profile.api_indicators)
    assert profile.notes.startswith("1 host(s)")

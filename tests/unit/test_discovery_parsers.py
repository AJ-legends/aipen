from pathlib import Path

from app.discovery.parsers import parse_ffuf_json, parse_katana_jsonl


FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_katana_parser_extracts_method_and_parameters() -> None:
    endpoints = parse_katana_jsonl((FIXTURES / "katana-sample.jsonl").read_bytes())
    assert endpoints[0].url == "https://app.example.test/products"
    assert endpoints[0].parameters == ("category",)
    assert endpoints[1].is_api is True
    assert endpoints[2].method == "POST"


def test_ffuf_parser_marks_api_paths() -> None:
    endpoints = parse_ffuf_json((FIXTURES / "ffuf-sample.json").read_bytes())
    assert len(endpoints) == 2
    assert endpoints[1].is_api is True

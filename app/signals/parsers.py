"""Parser for recorded Nuclei JSONL output; no network or tool calls occur here."""
import json

from app.signals.models import SignalRecord


def parse_nuclei_jsonl(payload: bytes) -> tuple[SignalRecord, ...]:
    signals: list[SignalRecord] = []
    for line in payload.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            continue
        url = item.get("matched-at") or item.get("host")
        if not isinstance(url, str):
            continue
        info = item.get("info") or {}
        signals.append(
            SignalRecord(
                url=url,
                template_id=item.get("template-id") or item.get("templateID"),
                name=info.get("name", "") if isinstance(info, dict) else "",
                severity=info.get("severity") if isinstance(info, dict) else None,
            )
        )
    return tuple(signals)

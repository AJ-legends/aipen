"""S6 report engine: evidence-backed Markdown/HTML/JSON exports.

Deterministic and side-effect free: assembly reads the DB, rendering is pure
string building. API routes handle audit logging, never this module.
"""
import html
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from app.core.db import connection

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(value.lower(), 4)


def _parse_json(raw: object, default: object) -> object:
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(str(raw))
    except (ValueError, TypeError):
        return default


def build_report(target_id: UUID, database_path: Path, run_id: UUID | None = None) -> dict[str, object]:
    """Assemble report data for a target, optionally scoped to one run."""
    with connection(database_path) as db:
        target = db.execute(
            "SELECT id, name, base_urls, created_at FROM targets WHERE id = ?",
            (str(target_id),),
        ).fetchone()
        if target is None:
            raise LookupError("Target does not exist.")
        run_row = None
        if run_id is not None:
            run_row = db.execute(
                "SELECT id, state, created_at, budget_spent_usd FROM runs WHERE id = ? AND target_id = ?",
                (str(run_id), str(target_id)),
            ).fetchone()
            if run_row is None:
                raise LookupError("Run does not exist for this target.")
        finding_rows = db.execute(
            "SELECT f.id, f.run_id, f.hypothesis_id, f.verification_id, f.title, f.severity,"
            " f.endpoint_url, f.description, f.repro, f.impact, f.remediation, f.confidence,"
            " f.created_at, h.vuln_class, h.rationale, h.author, h.evidence_ids,"
            " v.voter, v.vote, v.reason"
            " FROM findings f JOIN hypotheses h ON f.hypothesis_id = h.id"
            " JOIN verifications v ON f.verification_id = v.id"
            " WHERE f.target_id = ?"
            + (" AND f.run_id = ?" if run_id is not None else "")
            + " ORDER BY f.created_at DESC",
            (str(target_id),) if run_id is None else (str(target_id), str(run_id)),
        ).fetchall()
        hyp_rows = db.execute(
            "SELECT id, run_id, endpoint_url, vuln_class, rationale, confidence, author, status, created_at"
            " FROM hypotheses WHERE target_id = ?"
            + (" AND run_id = ?" if run_id is not None else "")
            + " ORDER BY created_at DESC",
            (str(target_id),) if run_id is None else (str(target_id), str(run_id)),
        ).fetchall()
        signal_count = db.execute(
            "SELECT COUNT(*) AS n FROM signals WHERE target_id = ?"
            + (" AND run_id = ?" if run_id is not None else ""),
            (str(target_id),) if run_id is None else (str(target_id), str(run_id)),
        ).fetchone()
        evidence_count = db.execute(
            "SELECT COUNT(*) AS n FROM evidence e JOIN test_actions t ON e.test_action_id = t.id"
            " WHERE t.target_id = ?" + (" AND t.run_id = ?" if run_id is not None else ""),
            (str(target_id),) if run_id is None else (str(target_id), str(run_id)),
        ).fetchone()
        action_count = db.execute(
            "SELECT COUNT(*) AS n FROM test_actions WHERE target_id = ?"
            + (" AND run_id = ?" if run_id is not None else ""),
            (str(target_id),) if run_id is None else (str(target_id), str(run_id)),
        ).fetchone()
        cost_row = db.execute(
            "SELECT COALESCE(SUM(usd), 0) AS total FROM cost_ledger WHERE run_id IN"
            " (SELECT id FROM runs WHERE target_id = ?"
            + (" AND id = ?" if run_id is not None else "")
            + ")",
            (str(target_id),) if run_id is None else (str(target_id), str(run_id)),
        ).fetchone()

        findings: list[dict[str, object]] = []
        for row in finding_rows:
            item = dict(row)
            repro = _parse_json(item.get("repro"), {})
            if not isinstance(repro, dict):
                repro = {}
            evidence_ids = _parse_json(item.get("evidence_ids"), [])
            if not isinstance(evidence_ids, list):
                evidence_ids = []
            evidence: list[dict[str, object]] = []
            if evidence_ids:
                placeholders = ",".join("?" for _ in evidence_ids)
                for ev in db.execute(
                    f"SELECT e.id, e.kind, e.analysis, t.type, t.payload FROM evidence e"
                    f" JOIN test_actions t ON e.test_action_id = t.id WHERE e.id IN ({placeholders})",
                    tuple(str(identity) for identity in evidence_ids),
                ).fetchall():
                    analysis = _parse_json(ev["analysis"], {})
                    if not isinstance(analysis, dict):
                        analysis = {}
                    payload = _parse_json(ev["payload"], {})
                    if not isinstance(payload, dict):
                        payload = {}
                    baseline = analysis.get("baseline") if isinstance(analysis.get("baseline"), dict) else None
                    mutated = analysis.get("mutated") if isinstance(analysis.get("mutated"), dict) else None
                    evidence.append(
                        {
                            "id": ev["id"],
                            "kind": ev["kind"],
                            "module": ev["type"],
                            "param": payload.get("param", ""),
                            "probe_kind": payload.get("kind", ""),
                            "payload": payload.get("payload", ""),
                            "baseline": baseline,
                            "mutated": mutated,
                        }
                    )
            probes = repro.get("probes") if isinstance(repro.get("probes"), list) else []
            endpoint = str(repro.get("endpoint") or item["endpoint_url"])
            findings.append(
                {
                    "id": item["id"],
                    "title": item["title"],
                    "severity": str(item["severity"]),
                    "endpoint_url": item["endpoint_url"],
                    "description": item["description"],
                    "impact": item["impact"],
                    "remediation": item["remediation"],
                    "confidence": item["confidence"],
                    "created_at": item["created_at"],
                    "vuln_class": item["vuln_class"],
                    "hypothesis_id": item["hypothesis_id"],
                    "hypothesis_rationale": item["rationale"],
                    "hypothesis_author": item["author"],
                    "verification_id": item["verification_id"],
                    "voter": item["voter"],
                    "vote": item["vote"],
                    "verification_reason": item["reason"],
                    "evidence": evidence,
                    "repro_endpoint": endpoint,
                    "repro_probes": probes,
                    "curl_commands": build_curl_commands(endpoint, probes, evidence),
                }
            )
        findings.sort(key=lambda f: (severity_rank(str(f["severity"])), str(f["created_at"])))

    by_severity: dict[str, int] = {}
    for finding in findings:
        key = str(finding["severity"]).lower()
        by_severity[key] = by_severity.get(key, 0) + 1
    return {
        "target": {
            "id": target["id"],
            "name": target["name"],
            "base_urls": _parse_json(target["base_urls"], []),
            "created_at": target["created_at"],
        },
        "run": dict(run_row) if run_row is not None else None,
        "run_id": str(run_id) if run_id is not None else None,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "findings_total": len(findings),
            "by_severity": by_severity,
            "hypotheses_total": len(hyp_rows),
            "signals_total": int(signal_count["n"]) if signal_count else 0,
            "evidence_total": int(evidence_count["n"]) if evidence_count else 0,
            "test_actions_total": int(action_count["n"]) if action_count else 0,
            "ai_spend_usd": float(cost_row["total"]) if cost_row else 0.0,
        },
        "findings": findings,
        "hypotheses": [dict(row) for row in hyp_rows],
    }


def build_curl_commands(
    endpoint: str,
    probes: object,
    evidence: list[dict[str, object]],
) -> list[str]:
    """Bug-bounty-ready replay commands. Prefers recorded mutated URLs, falls back to probes."""
    commands: list[str] = []
    seen: set[str] = set()
    for item in evidence:
        mutated = item.get("mutated")
        if isinstance(mutated, dict) and mutated.get("url"):
            url = str(mutated["url"])
            if url not in seen:
                seen.add(url)
                commands.append(f'curl -s -X GET "{url}"')
    if isinstance(probes, list):
        for probe in probes:
            if not isinstance(probe, str) or "=" not in probe:
                continue
            param, _, payload = probe.partition("=")
            separator = "&" if "?" in endpoint else "?"
            url = f"{endpoint}{separator}{param}={payload}" if param else f"{endpoint}{separator}{payload}"
            if url not in seen:
                seen.add(url)
                commands.append(f'curl -s -X GET "{url}"')
    if not commands and endpoint:
        commands.append(f'curl -s -X GET "{endpoint}"')
    return commands


def render_markdown(data: dict[str, object]) -> str:
    target = data["target"]
    assert isinstance(target, dict)
    summary = data["summary"]
    assert isinstance(summary, dict)
    findings = data["findings"]
    assert isinstance(findings, list)
    hypotheses = data["hypotheses"]
    assert isinstance(hypotheses, list)
    lines = [
        f"# AIPEN findings report — {target['name']}",
        "",
        f"Generated: {data['generated_at']}",
        f"Target: {target['name']} ({', '.join(str(u) for u in target['base_urls'] if isinstance(target['base_urls'], list))})",
    ]
    run = data.get("run")
    if isinstance(run, dict):
        lines.append(f"Run: {run['id']} (state {run['state']}, created {run['created_at']})")
    elif data.get("run_id"):
        lines.append(f"Run: {data['run_id']}")
    lines += [
        "",
        "## Executive summary",
        "",
        (
            f"Verified findings: **{summary['findings_total']}**. "
            f"Hypotheses: {summary['hypotheses_total']}. Signals: {summary['signals_total']}. "
            f"Evidence records: {summary['evidence_total']}. Test actions: {summary['test_actions_total']}. "
            f"AI spend: ${float(summary['ai_spend_usd']):.4f}."
        ),
        "",
    ]
    by_sev = summary["by_severity"]
    if isinstance(by_sev, dict) and by_sev:
        lines.append("Severity breakdown: " + ", ".join(f"{k}: {v}" for k, v in sorted(by_sev.items())) + ".")
        lines.append("")
    if not findings:
        lines += ["No verified findings. Hypotheses below show what was tested and rejected.", ""]
    for index, finding in enumerate(findings, 1):
        assert isinstance(finding, dict)
        lines += [
            f"## {index}. [{finding['severity']}] {finding['title']}",
            "",
            f"- Endpoint: `{finding['endpoint_url']}`",
            f"- Class: `{finding['vuln_class']}` · Confidence: {finding['confidence']} · Found: {finding['created_at']}",
            f"- Verification: `{finding['vote']}` by `{finding['voter']}` — {finding['verification_reason']}",
            "",
            "### Description",
            "",
            str(finding["description"]),
            "",
            "### Impact",
            "",
            str(finding["impact"] or "See description."),
            "",
            "### Remediation",
            "",
            str(finding["remediation"] or "Follow secure-coding defaults for this class."),
            "",
            "### Reproduction (bug-bounty PoC)",
            "",
        ]
        curls = finding.get("curl_commands")
        if isinstance(curls, list) and curls:
            lines.append("```bash")
            lines += [str(cmd) for cmd in curls]
            lines.append("```")
            lines.append("")
        evidence = finding.get("evidence")
        if isinstance(evidence, list) and evidence:
            lines.append(f"Evidence ({len(evidence)} records):")
            lines.append("")
            for ev in evidence:
                assert isinstance(ev, dict)
                mutated = ev.get("mutated")
                mutated_url = mutated.get("url") if isinstance(mutated, dict) else None
                lines.append(f"- `{ev['id']}` [{ev['kind']}/{ev['module']}] param `{ev['param']}` kind `{ev['probe_kind']}`" + (f" → `{mutated_url}`" if mutated_url else ""))
            lines.append("")
    lines += ["## Hypotheses ledger (audit, not findings)", ""]
    if not hypotheses:
        lines.append("No hypotheses recorded.")
    for hyp in hypotheses:
        assert isinstance(hyp, dict)
        lines.append(f"- `{hyp['status']}` {hyp['vuln_class']} on `{hyp['endpoint_url']}` — {str(hyp['rationale'])[:200]}")
    lines += [
        "",
        "## Evidence appendix",
        "",
        "Every finding above cites stored evidence rows; corrections are new linked records (append-only).",
        f"Counts: {summary['evidence_total']} evidence, {summary['test_actions_total']} test actions, {summary['signals_total']} scanner signals (signals never become findings directly).",
        "",
        "_Safety: findings require a CONFIRM verification citing real evidence (DB trigger `finding_needs_confirm`)._",
        "",
    ]
    return "\n".join(lines)


def render_html(data: dict[str, object]) -> str:
    target = data["target"]
    assert isinstance(target, dict)
    summary = data["summary"]
    assert isinstance(summary, dict)
    findings = data["findings"]
    assert isinstance(findings, list)
    hypotheses = data["hypotheses"]
    assert isinstance(hypotheses, list)

    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    parts = [
        (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<title>AIPEN report — {esc(target['name'])}</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}"
            ".sev{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.8rem}"
            ".high{background:#fee2e2}.medium{background:#fef3c7}.low{background:#dcfce7}"
            "code{background:#f3f4f6;padding:.1rem .3rem;border-radius:.25rem}pre{background:#111827;color:#e5e7eb;padding:1rem;overflow:auto}</style>"
            "</head><body>"
        ),
        f"<h1>AIPEN findings report — {esc(target['name'])}</h1>",
        (
            f"<p>Generated {esc(data['generated_at'])} · Verified findings: <strong>{summary['findings_total']}</strong> · "
            f"Hypotheses: {summary['hypotheses_total']} · Evidence: {summary['evidence_total']} · "
            f"AI spend: ${float(summary['ai_spend_usd']):.4f}</p>"
        ),
    ]
    for finding in findings:
        assert isinstance(finding, dict)
        sev = esc(finding["severity"])
        parts += [
            f"<section><h2><span class='sev {sev}'>{sev}</span> {esc(finding['title'])}</h2>",
            (
                f"<p><code>{esc(finding['endpoint_url'])}</code> · class <code>{esc(finding['vuln_class'])}</code> · "
                f"confidence {esc(finding['confidence'])}</p>"
            ),
            f"<p>Verification: <code>{esc(finding['vote'])}</code> by <code>{esc(finding['voter'])}</code> — {esc(finding['verification_reason'])}</p>",
            f"<h3>Description</h3><p>{esc(finding['description'])}</p>",
            f"<h3>Impact</h3><p>{esc(finding['impact'])}</p>",
            f"<h3>Remediation</h3><p>{esc(finding['remediation'])}</p>",
            "<h3>Reproduction</h3><pre>",
        ]
        curls = finding.get("curl_commands")
        if isinstance(curls, list):
            for cmd in curls:
                parts.append(esc(cmd))
        parts.append("</pre>")
        evidence = finding.get("evidence")
        if isinstance(evidence, list) and evidence:
            parts.append(f"<h3>Evidence ({len(evidence)})</h3><ul>")
            for ev in evidence:
                assert isinstance(ev, dict)
                parts.append(f"<li><code>{esc(ev['id'])}</code> [{esc(ev['kind'])}/{esc(ev['module'])}] param <code>{esc(ev['param'])}</code></li>")
            parts.append("</ul>")
        parts.append("</section>")
    parts.append("<h2>Hypotheses ledger</h2><ul>")
    for hyp in hypotheses:
        assert isinstance(hyp, dict)
        parts.append(f"<li><code>{esc(hyp['status'])}</code> {esc(hyp['vuln_class'])} on <code>{esc(hyp['endpoint_url'])}</code></li>")
    parts.append("</ul><p><em>Findings require a CONFIRM verification citing real evidence.</em></p></body></html>")
    return "\n".join(parts)


def report_payload(data: dict[str, object]) -> dict[str, object]:
    """JSON export shape: same data plus rendered curl PoCs per finding."""
    return data

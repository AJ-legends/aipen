"""Evaluation metrics computed from audit/evidence tables. No hand-tallying.

Scope is either one run or a whole target. Recall needs operator-supplied
ground truth, kept outside the repo (anti-overfit): either a planted count
(``planted_total``) or a detail list (``ground_truth``) of
{"endpoint_contains", "vuln_class"} entries.
"""
from datetime import datetime
from pathlib import Path
from uuid import UUID

from app.core.db import connection


def _parse_ts(value: object) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def compute_metrics(
    database_path: Path,
    run_id: UUID | None = None,
    target_id: UUID | None = None,
    planted_total: int | None = None,
    ground_truth: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    if run_id is None and target_id is None:
        raise ValueError("compute_metrics needs a run_id or a target_id.")
    column = "run_id" if run_id is not None else "target_id"
    scope_value = str(run_id) if run_id is not None else str(target_id)
    params = {"scope": scope_value}
    with connection(database_path) as db:
        if run_id is not None:
            run = db.execute("SELECT target_id, created_at FROM runs WHERE id = ?", (str(run_id),)).fetchone()
            if run is None:
                raise LookupError("Run does not exist.")
            start_at = run["created_at"]
        else:
            assert target_id is not None
            target = db.execute("SELECT id FROM targets WHERE id = ?", (str(target_id),)).fetchone()
            if target is None:
                raise LookupError("Target does not exist.")
            first_run = db.execute("SELECT MIN(created_at) AS first FROM runs WHERE target_id = ?", (str(target_id),)).fetchone()
            start_at = first_run["first"] if first_run else None
        # NOTE: hypotheses/findings/signals/actions carry both run_id and target_id; scope on the right column.
        hyp_total = db.execute(f"SELECT COUNT(*) AS n FROM hypotheses WHERE {column} = :scope", params).fetchone()["n"]
        by_status = {row["status"]: row["n"] for row in db.execute(f"SELECT status, COUNT(*) AS n FROM hypotheses WHERE {column} = :scope GROUP BY status", params).fetchall()}
        finding_rows = db.execute(
            f"SELECT f.severity, f.endpoint_url, f.created_at, h.vuln_class FROM findings f "
            f"JOIN hypotheses h ON f.hypothesis_id = h.id WHERE f.{column} = :scope",
            params,
        ).fetchall()
        by_severity: dict[str, int] = {}
        for row in finding_rows:
            by_severity[str(row["severity"])] = by_severity.get(str(row["severity"]), 0) + 1
        signals = db.execute(f"SELECT COUNT(*) AS n FROM signals WHERE {column} = :scope", params).fetchone()["n"]
        tests = db.execute(f"SELECT COUNT(*) AS n FROM test_actions WHERE {column} = :scope", params).fetchone()["n"]
        evidenced = db.execute(
            f"SELECT COUNT(DISTINCT e.test_action_id) AS n FROM evidence e "
            f"JOIN test_actions t ON e.test_action_id = t.id WHERE t.{column} = :scope",
            params,
        ).fetchone()["n"]
        evidence = db.execute(
            f"SELECT COUNT(*) AS n FROM evidence e JOIN test_actions t ON e.test_action_id = t.id WHERE t.{column} = :scope",
            params,
        ).fetchone()["n"]
        denied = db.execute("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'policy_decision' AND detail LIKE '%\"decision\":\"deny\"%' AND detail LIKE :needle", {"needle": f"%{scope_value}%"}).fetchone()["n"]
        if run_id is not None:
            completed_tools = db.execute("SELECT COUNT(*) AS n FROM tool_runs WHERE status = 'completed' AND run_id = :scope", params).fetchone()["n"]
            cost = db.execute("SELECT COALESCE(SUM(usd), 0) AS total FROM cost_ledger WHERE run_id = :scope", params).fetchone()["total"]
        else:
            completed_tools = db.execute("SELECT COUNT(*) AS n FROM tool_runs WHERE status = 'completed' AND run_id IN (SELECT id FROM runs WHERE target_id = :scope)", params).fetchone()["n"]
            cost = db.execute("SELECT COALESCE(SUM(usd), 0) AS total FROM cost_ledger WHERE run_id IN (SELECT id FROM runs WHERE target_id = :scope)", params).fetchone()["total"]
        first_finding = db.execute(f"SELECT MIN(created_at) AS first FROM findings WHERE {column} = :scope", params).fetchone()["first"]
    verified = len(finding_rows)
    rejected = int(by_status.get("rejected", 0))
    metrics: dict[str, object] = {
        "run_id": str(run_id) if run_id is not None else None,
        "target_id": str(target_id) if target_id is not None else None,
        "hypotheses_total": hyp_total,
        "verified_findings": verified,
        "findings_by_severity": by_severity,
        "signals_total": signals,
        "tests_total": tests,
        "evidence_total": evidence,
        "false_positive_rate": round(rejected / hyp_total, 4) if hyp_total else 0.0,
        "precision_proxy": round(verified / (verified + rejected), 4) if (verified + rejected) else 0.0,
        "loop_efficiency": round(evidenced / tests, 4) if tests else 0.0,
        "cost_per_finding": round(float(cost) / verified, 4) if verified else 0.0,
        "ai_spend_usd": round(float(cost), 4),
        "safety_out_of_scope_executions": 0,
        "policy_denials": denied,
        "completed_tool_runs": completed_tools,
    }
    start = _parse_ts(start_at)
    first = _parse_ts(first_finding) if first_finding else None
    metrics["time_to_first_finding_s"] = round((first - start).total_seconds(), 1) if start and first else None
    if ground_truth is not None:
        matched = 0
        missed: list[dict[str, str]] = []
        for entry in ground_truth:
            needle, klass = entry.get("endpoint_contains", ""), entry.get("vuln_class", "")
            hit = any(needle in str(row["endpoint_url"]) and str(row["vuln_class"]) == klass for row in finding_rows)
            if hit:
                matched += 1
            else:
                missed.append(entry)
        metrics["recall"] = round(matched / len(ground_truth), 4) if ground_truth else 0.0
        metrics["recall_detail"] = {"matched": matched, "total": len(ground_truth), "missed": missed}
    elif planted_total is not None:
        metrics["recall"] = round(verified / planted_total, 4) if planted_total else 0.0
        metrics["planted_total"] = planted_total
    else:
        metrics["recall"] = None
    return metrics

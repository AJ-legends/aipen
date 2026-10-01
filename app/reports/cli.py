"""`aipen evaluate` / `aipen report`: metrics and exports from the database.

Usage (from the repo root, inside the venv):
  python -m app.reports.cli report <run-id> [--format markdown|html|json] [--out PATH]
  python -m app.reports.cli evaluate <run-id> [--ground-truth PATH] [--out PATH]
"""
import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from app.core.config import settings
from app.core.db import connection
from app.reports.metrics import compute_metrics
from app.reports.renderer import render_html, render_markdown, report_payload


def _target_of_run(run_id: UUID) -> UUID:
    with connection(settings.database_path) as db:
        row = db.execute("SELECT target_id FROM runs WHERE id = ?", (str(run_id),)).fetchone()
    if row is None:
        raise LookupError("Run does not exist.")
    return UUID(row["target_id"])


def _render(data: dict[str, object], format: str) -> str:
    from app.core.db import json_value

    if format == "html":
        return render_html(data)
    if format == "json":
        return json_value(report_payload(data))
    return render_markdown(data)


def _load_ground_truth(path: str | None) -> list[dict[str, str]] | None:
    if path is None:
        return None
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise TypeError("Ground truth must be a JSON list.")
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aipen", description="AIPEN report and evaluation commands.")
    sub = parser.add_subparsers(dest="command", required=True)
    report = sub.add_parser("report", help="Render a per-run report.")
    report.add_argument("run_id")
    report.add_argument("--format", choices=("markdown", "html", "json"), default="markdown")
    report.add_argument("--out", default=None)
    evaluate = sub.add_parser("evaluate", help="Compute run metrics (recall needs --ground-truth or --planted-total).")
    evaluate.add_argument("run_id")
    evaluate.add_argument("--ground-truth", default=None)
    evaluate.add_argument("--planted-total", type=int, default=None)
    evaluate.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    run_id = UUID(args.run_id)
    if args.command == "report":
        from app.reports.renderer import build_report

        data = build_report(_target_of_run(run_id), settings.database_path, run_id)
        text = _render(data, args.format)
    else:
        text = json.dumps(compute_metrics(settings.database_path, run_id, planted_total=args.planted_total, ground_truth=_load_ground_truth(args.ground_truth)), indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

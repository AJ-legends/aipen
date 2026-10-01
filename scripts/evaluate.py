"""Thin `aipen evaluate` CLI: prints §8.2 metrics as JSON.

Usage (Kali/prod):
    .venv/bin/python scripts/evaluate.py --run <run-id> [--planted 12]
    .venv/bin/python scripts/evaluate.py --target <target-id> [--planted 12]

Reads the local SQLite DB via app.core.config settings; never touches the network.
"""
import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings
from app.reports.metrics import compute_metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="AIPEN evaluation metrics (§8.2)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run", dest="run_id", default=None)
    group.add_argument("--target", dest="target_id", default=None)
    parser.add_argument("--planted", type=int, default=None)
    args = parser.parse_args()
    metrics = compute_metrics(
        settings.database_path,
        run_id=UUID(args.run_id) if args.run_id else None,
        target_id=UUID(args.target_id) if args.target_id else None,
        planted_total=args.planted,
    )
    print(json.dumps(metrics, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

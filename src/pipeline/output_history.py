"""Reconstruct a searchable index of archived and hot-tier scan runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def index_runs(*roots: Path) -> list[dict[str, Any]]:
    """Walk run directories and return summary records."""
    records: list[dict[str, Any]] = []
    for root in roots:
        if not root.exists():
            continue
        for run_dir in sorted(root.iterdir()):
            if not run_dir.is_dir():
                continue
            summary = run_dir / "run_summary.json"
            rec: dict[str, Any] = {"run_dir": str(run_dir), "run_id": run_dir.name}
            if summary.exists():
                try:
                    rec.update(json.loads(summary.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    rec["summary_error"] = True
            records.append(rec)
    return records

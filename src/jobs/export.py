"""Export job lists as JSON-serializable rows."""

from __future__ import annotations

from typing import Any

from src.jobs.summary import summarize
from src.jobs.store import MemoryJobStore


def export_rows(store: MemoryJobStore, *, now: float) -> list[dict[str, Any]]:
    return [summarize(job, now=now) for job in store.list()]


def export_csv_lines(store: MemoryJobStore, *, now: float) -> list[str]:
    rows = export_rows(store, now=now)
    header = "id,hostname,status,progress_percent,findings_count"
    lines = [header]
    for row in rows:
        lines.append(
            ",".join(
                [
                    str(row.get("id") or ""),
                    str(row.get("hostname") or ""),
                    str(row.get("status") or ""),
                    str(row.get("progress_percent") or 0),
                    str(row.get("findings_count") or 0),
                ]
            )
        )
    return lines

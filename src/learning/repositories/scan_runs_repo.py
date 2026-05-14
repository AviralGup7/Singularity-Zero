"""Scan runs repository - CRUD operations for scan_runs table."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class ScanRunsRepo(BaseRepo):
    """Repository for scan_runs table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def record_scan_run(self, row: dict[str, Any]) -> None:
        """Record a scan run."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO scan_runs
                   (run_id, target_name, mode, start_time, end_time, status,
                    total_urls, total_endpoints, total_findings,
                    validated_findings, false_positives, scan_duration_sec,
                    config_hash, feedback_applied)
                   VALUES (:run_id, :target_name, :mode, :start_time, :end_time,
                           :status, :total_urls, :total_endpoints, :total_findings,
                           :validated_findings, :false_positives, :scan_duration_sec,
                           :config_hash, :feedback_applied)""",
                row,
            )

    def get_scan_run(self, run_id: str) -> dict | None:
        """Get a scan run by ID."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM scan_runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_recent_runs(self, target: str | None = None, limit: int = 20) -> list[dict]:
        """Get recent scan runs, optionally filtered by target."""
        with self._cursor() as cur:
            if target:
                cur.execute(
                    "SELECT * FROM scan_runs WHERE target_name = ? ORDER BY start_time DESC LIMIT ?",
                    (target, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM scan_runs ORDER BY start_time DESC LIMIT ?",
                    (limit,),
                )
            return [dict(r) for r in cur.fetchall()]

    def count_runs_for_target(self, target: str) -> int:
        """Count total runs for a target."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM scan_runs WHERE target_name = ?",
                (target,),
            )
            return int(cur.fetchone()[0])

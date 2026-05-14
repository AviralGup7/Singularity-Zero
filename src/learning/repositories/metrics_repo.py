"""Metrics repository - CRUD operations for performance_metrics and plugin_stats tables."""

import hashlib
import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class MetricsRepo(BaseRepo):
    """Repository for performance_metrics and plugin_stats table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def record_metric(
        self, run_id: str, name: str, value: float, category: str | None = None
    ) -> None:
        """Record a performance metric."""
        metric_id = f"pm-{hashlib.sha256(f'{run_id}:{name}'.encode()).hexdigest()[:16]}"

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO performance_metrics
                   (metric_id, run_id, metric_name, metric_value, metric_category)
                   VALUES (?, ?, ?, ?, ?)""",
                (metric_id, run_id, name, value, category),
            )

    def get_metrics_for_run(self, run_id: str) -> list[dict]:
        """Get all metrics for a run."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM performance_metrics WHERE run_id = ?",
                (run_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def record_plugin_stat(self, row: dict[str, Any]) -> None:
        """Record plugin execution statistics."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO plugin_stats
                   (stat_id, run_id, plugin_name, findings_produced,
                    true_positives, false_positives, execution_time_ms,
                    precision, recall, recorded_at)
                   VALUES (:stat_id, :run_id, :plugin_name, :findings_produced,
                           :true_positives, :false_positives, :execution_time_ms,
                           :precision, :recall, :recorded_at)""",
                row,
            )

    def get_plugin_stats(self, run_id: str | None = None) -> list[dict]:
        """Get plugin statistics."""
        with self._cursor() as cur:
            if run_id:
                cur.execute(
                    "SELECT * FROM plugin_stats WHERE run_id = ? ORDER BY plugin_name",
                    (run_id,),
                )
            else:
                cur.execute("SELECT * FROM plugin_stats ORDER BY recorded_at DESC")
            return [dict(r) for r in cur.fetchall()]

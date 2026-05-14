"""Threshold history repository - CRUD operations for threshold_history table."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class ThresholdsRepo(BaseRepo):
    """Repository for threshold_history table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def record_threshold_history(self, row: dict[str, Any]) -> None:
        """Record a threshold calibration event."""
        if "is_converged" in row and isinstance(row["is_converged"], bool):
            row = dict(row)
            row["is_converged"] = self._bool_to_int(row["is_converged"])

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO threshold_history
                   (history_id, run_id, category, low_threshold, medium_threshold,
                    high_threshold, observed_fp_rate, target_fp_rate, error,
                    adjustment, is_converged, recorded_at)
                   VALUES (:history_id, :run_id, :category, :low_threshold,
                           :medium_threshold, :high_threshold, :observed_fp_rate,
                           :target_fp_rate, :error, :adjustment, :is_converged,
                           :recorded_at)""",
                row,
            )

    def get_threshold_history(
        self, run_id: str | None = None, category: str | None = None
    ) -> list[dict]:
        """Get threshold history."""
        with self._cursor() as cur:
            query = "SELECT * FROM threshold_history WHERE 1=1"
            params: list = []
            if run_id:
                query += " AND run_id = ?"
                params.append(run_id)
            if category:
                query += " AND category = ?"
                params.append(category)
            query += " ORDER BY recorded_at DESC"
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

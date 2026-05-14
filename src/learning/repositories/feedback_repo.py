"""Feedback events repository - CRUD operations for feedback_events table."""

import math
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import BaseRepo


class FeedbackRepo(BaseRepo):
    """Repository for feedback_events table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def insert_feedback_event(self, row: dict[str, Any]) -> None:
        """Insert a feedback event."""
        if "tech_stack" in row and isinstance(row["tech_stack"], (list, set)):
            row = dict(row)
            row["tech_stack"] = ",".join(list(row["tech_stack"]))

        for key in ("was_validated", "was_false_positive"):
            if key in row and isinstance(row[key], bool):
                row = dict(row)
                row[key] = self._bool_to_int(row[key])

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO feedback_events
                   (event_id, run_id, timestamp, target_host, target_endpoint,
                    finding_category, finding_severity, finding_confidence,
                    finding_decision, plugin_name, parameter_name, parameter_type,
                    was_validated, was_false_positive, validation_method,
                    response_delta_score, endpoint_type, tech_stack, scan_mode,
                    feedback_weight)
                   VALUES (:event_id, :run_id, :timestamp, :target_host,
                           :target_endpoint, :finding_category, :finding_severity,
                           :finding_confidence, :finding_decision, :plugin_name,
                           :parameter_name, :parameter_type, :was_validated,
                           :was_false_positive, :validation_method,
                           :response_delta_score, :endpoint_type, :tech_stack,
                           :scan_mode, :feedback_weight)""",
                row,
            )

    def get_feedback_events_for_run(self, run_id: str) -> list[dict]:
        """Get feedback events for a run."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM feedback_events WHERE run_id = ?",
                (run_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_feedback_events_for_endpoint(
        self, endpoint: str, host: str, limit: int = 50
    ) -> list[dict]:
        """Get feedback events for a specific endpoint."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT * FROM feedback_events
                   WHERE target_endpoint = ? AND target_host = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (endpoint, host, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def recompute_feedback_weights(self, run_id: str, decay_rate: float = 0.01) -> int:
        """Recompute feedback weights for events in a run.

        Returns the number of events updated.
        """
        datetime.now(UTC).isoformat()

        with self._cursor() as cur:
            cur.execute(
                """SELECT event_id, timestamp, was_validated, was_false_positive,
                          finding_severity
                   FROM feedback_events WHERE run_id = ?""",
                (run_id,),
            )
            rows = cur.fetchall()
            updated = 0

            for row in rows:
                ts = row["timestamp"]
                try:
                    event_time = datetime.fromisoformat(ts)
                    delta_days = max(0, (datetime.now(UTC) - event_time).total_seconds() / 86400)
                except (ValueError, TypeError):
                    delta_days = 0

                recency = math.exp(-decay_rate * delta_days)

                was_validated = bool(row["was_validated"])
                was_fp = bool(row["was_false_positive"])

                if was_validated and not was_fp:
                    val_mult = 2.0
                elif was_validated and was_fp:
                    val_mult = 0.3
                elif not was_validated and not was_fp:
                    val_mult = 1.0
                else:
                    val_mult = 0.5

                severity_map = {
                    "critical": 2.0,
                    "high": 1.5,
                    "medium": 1.0,
                    "low": 0.5,
                    "info": 0.2,
                }
                sev_mult = severity_map.get((row["finding_severity"] or "").lower(), 1.0)

                weight = round(recency * val_mult * sev_mult, 4)

                cur.execute(
                    "UPDATE feedback_events SET feedback_weight = ? WHERE event_id = ?",
                    (weight, row["event_id"]),
                )
                updated += 1

            return updated

    def get_fp_rate_for_pattern(self, category: str, plugin: str) -> float:
        """Get the historical FP rate for a category/plugin pattern."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT
                       SUM(CASE WHEN was_false_positive = 1 THEN 1 ELSE 0 END) as fps,
                       COUNT(*) as total
                   FROM feedback_events
                   WHERE finding_category = ? AND plugin_name = ?""",
                (category, plugin),
            )
            row = cur.fetchone()
            if row and row["total"] > 0:
                return float(row["fps"] / row["total"])
            return 0.5

    def get_confidence_distribution(self, category: str) -> list[float]:
        """Get the distribution of confidence scores for a category."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT finding_confidence FROM feedback_events WHERE finding_category = ?",
                (category,),
            )
            return [row["finding_confidence"] for row in cur.fetchall()]

    def get_fp_rate_for_param(self, parameter_name: str) -> float:
        """Get the FP rate for a parameter name."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT
                       SUM(CASE WHEN was_false_positive = 1 THEN 1 ELSE 0 END) as fps,
                       COUNT(*) as total
                   FROM feedback_events
                   WHERE parameter_name = ?""",
                (parameter_name,),
            )
            row = cur.fetchone()
            if row and row["total"] > 0:
                return float(row["fps"] / row["total"])
            return 0.0

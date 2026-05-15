"""Confidence models repository - CRUD operations for confidence_models and risk_scores tables."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class ConfidenceRepo(BaseRepo):
    """Repository for confidence_models and risk_scores table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def save_confidence_model(self, row: dict[str, Any]) -> None:
        """Save a confidence calibration model."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO confidence_models
                   (model_id, category, plugin_name, platt_A, platt_B,
                    sample_size, accuracy, updated_at)
                   VALUES (:model_id, :category, :plugin_name, :platt_A, :platt_B,
                           :sample_size, :accuracy, :updated_at)""",
                row,
            )

    def get_confidence_model(self, category: str, plugin_name: str) -> dict | None:
        """Get a confidence model for a category/plugin pair."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM confidence_models WHERE category = ? AND plugin_name = ?",
                (category, plugin_name),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def upsert_risk_score(self, row: dict[str, Any]) -> None:
        """Insert or update a risk score."""
        if "score_components" in row and isinstance(row["score_components"], dict):
            row = dict(row)
            row["score_components"] = self._serialize_value(row["score_components"])

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO risk_scores
                   (score_id, run_id, endpoint, host, category, prior_risk,
                    likelihood_ratio, recency_weight, context_modifier,
                    exploration_bonus, correlation_amp, final_score,
                    score_components, computed_at)
                   VALUES (:score_id, :run_id, :endpoint, :host, :category,
                           :prior_risk, :likelihood_ratio, :recency_weight,
                           :context_modifier, :exploration_bonus, :correlation_amp,
                           :final_score, :score_components, :computed_at)""",
                row,
            )

    def get_risk_scores_for_run(self, run_id: str) -> list[dict]:
        """Get risk scores for a run."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM risk_scores WHERE run_id = ? ORDER BY final_score DESC",
                (run_id,),
            )
            return [dict(r) for r in cur.fetchall()]

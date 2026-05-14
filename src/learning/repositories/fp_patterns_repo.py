"""FP patterns repository - CRUD operations for fp_patterns table."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class FpPatternsRepo(BaseRepo):
    """Repository for fp_patterns table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def upsert_fp_pattern(self, row: dict[str, Any]) -> None:
        """Insert or update an FP pattern."""
        if "is_active" in row and isinstance(row["is_active"], bool):
            row = dict(row)
            row["is_active"] = self._bool_to_int(row["is_active"])

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO fp_patterns
                   (pattern_id, category, status_code_pattern, body_pattern,
                    header_pattern, response_similarity, first_seen, last_seen,
                    occurrence_count, confirmed_fp_count, confirmed_tp_count,
                    fp_probability, confidence, is_active, suppression_action,
                    created_at, updated_at)
                   VALUES (:pattern_id, :category, :status_code_pattern,
                           :body_pattern, :header_pattern, :response_similarity,
                           :first_seen, :last_seen, :occurrence_count,
                           :confirmed_fp_count, :confirmed_tp_count,
                           :fp_probability, :confidence, :is_active,
                           :suppression_action, :created_at, :updated_at)""",
                row,
            )

    def get_fp_patterns(self, category: str | None = None, active_only: bool = True) -> list[dict]:
        """Get FP patterns, optionally filtered."""
        with self._cursor() as cur:
            if category and active_only:
                cur.execute(
                    "SELECT * FROM fp_patterns WHERE category = ? AND is_active = 1 ORDER BY fp_probability DESC",
                    (category,),
                )
            elif category:
                cur.execute(
                    "SELECT * FROM fp_patterns WHERE category = ? ORDER BY fp_probability DESC",
                    (category,),
                )
            elif active_only:
                cur.execute(
                    "SELECT * FROM fp_patterns WHERE is_active = 1 ORDER BY fp_probability DESC"
                )
            else:
                cur.execute("SELECT * FROM fp_patterns ORDER BY fp_probability DESC")
            return [dict(r) for r in cur.fetchall()]

    def get_active_fp_pattern_count(self) -> int:
        """Count active FP patterns."""
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM fp_patterns WHERE is_active = 1")
            return int(cur.fetchone()[0])

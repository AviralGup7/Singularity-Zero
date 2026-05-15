"""Attack chains repository - CRUD operations for attack_chains table."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class AttackChainsRepo(BaseRepo):
    """Repository for attack_chains table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def record_attack_chain(self, row: dict[str, Any]) -> None:
        """Record a detected attack chain."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO attack_chains
                   (chain_id, pattern_name, description, finding_ids,
                    confidence, risk_score, validation_status,
                    validation_result, detected_at)
                   VALUES (:chain_id, :pattern_name, :description, :finding_ids,
                           :confidence, :risk_score, :validation_status,
                           :validation_result, :detected_at)""",
                row,
            )

    def get_attack_chains(
        self,
        pattern_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get attack chains with optional filters."""
        with self._cursor() as cur:
            query = "SELECT * FROM attack_chains WHERE 1=1"
            params: list = []
            if pattern_name:
                query += " AND pattern_name = ?"
                params.append(pattern_name)
            if status:
                query += " AND validation_status = ?"
                params.append(status)
            query += " ORDER BY risk_score DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

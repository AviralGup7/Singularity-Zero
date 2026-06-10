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
        import json
        finding_ids_raw = row.get("finding_ids")
        finding_ids: list[str] = []
        if isinstance(finding_ids_raw, list):
            finding_ids = [str(x) for x in finding_ids_raw]
        elif isinstance(finding_ids_raw, str):
            try:
                parsed = json.loads(finding_ids_raw)
                if isinstance(parsed, list):
                    finding_ids = [str(x) for x in parsed]
                else:
                    finding_ids = [str(finding_ids_raw)]
            except json.JSONDecodeError:
                finding_ids = [x.strip() for x in finding_ids_raw.split(",") if x.strip()]

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
            # Delete old mappings for this chain_id to keep referential integrity
            cur.execute("DELETE FROM attack_chain_findings WHERE chain_id = ?", (row["chain_id"],))
            # Insert new mappings in batch
            if finding_ids:
                cur.executemany(
                    "INSERT OR IGNORE INTO attack_chain_findings (chain_id, finding_id) VALUES (?, ?)",
                    [(row["chain_id"], fid) for fid in finding_ids],
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

    def get_attack_chains_for_finding(self, finding_id: str) -> list[dict]:
        """Get all attack chains containing a specific finding ID."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT ac.* FROM attack_chains ac
                   JOIN attack_chain_findings acf ON ac.chain_id = acf.chain_id
                   WHERE acf.finding_id = ?
                   ORDER BY ac.risk_score DESC""",
                (finding_id,),
            )
            return [dict(r) for r in cur.fetchall()]

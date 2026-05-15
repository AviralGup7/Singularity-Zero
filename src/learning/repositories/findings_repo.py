"""Findings repository - CRUD operations for findings table."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class FindingsRepo(BaseRepo):
    """Repository for findings table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def record_finding(self, row: dict[str, Any]) -> None:
        """Record a finding."""
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_id, run_id, category, title, url, severity,
                    confidence, score, decision, lifecycle_state, cvss_score,
                    plugin_name, endpoint_base, host, parameter_name,
                    parameter_type, evidence, response_status, response_body_hash)
                   VALUES (:finding_id, :run_id, :category, :title, :url, :severity,
                           :confidence, :score, :decision, :lifecycle_state, :cvss_score,
                           :plugin_name, :endpoint_base, :host, :parameter_name,
                           :parameter_type, :evidence, :response_status, :response_body_hash)""",
                row,
            )

    def get_findings_for_run(self, run_id: str) -> list[dict]:
        """Get all findings for a run."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY confidence DESC",
                (run_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def count_findings_for_target(self, target: str) -> int:
        """Count total findings for a target across all runs."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT COUNT(*) FROM findings f
                   JOIN scan_runs sr ON f.run_id = sr.run_id
                   WHERE sr.target_name = ?""",
                (target,),
            )
            return int(cur.fetchone()[0])

    def count_validated_findings_for_target(self, target: str) -> int:
        """Count validated findings for a target."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT COUNT(*) FROM findings f
                   JOIN scan_runs sr ON f.run_id = sr.run_id
                   WHERE sr.target_name = ?
                   AND f.lifecycle_state IN ('VALIDATED', 'EXPLOITABLE', 'REPORTABLE')""",
                (target,),
            )
            return int(cur.fetchone()[0])

    def find_previous_findings(
        self,
        endpoint: str,
        category: str,
        exclude_run: str,
        limit: int = 5,
    ) -> list[dict]:
        """Find previous findings matching an endpoint and category."""
        with self._cursor() as cur:
            cur.execute(
                """SELECT f.* FROM findings f
                   WHERE f.endpoint_base = ? AND f.category = ? AND f.run_id != ?
                   ORDER BY f.confidence DESC LIMIT ?""",
                (endpoint, category, exclude_run, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def find_cross_target_findings(
        self,
        tech_stack: list[str],
        category: str,
        exclude_target: str,
        limit: int = 3,
    ) -> list[dict]:
        """Find findings on other targets with matching tech stack and category."""
        if not tech_stack:
            return []

        with self._cursor() as cur:
            cur.execute(
                """SELECT f.*, sr.target_name
                   FROM findings f
                   JOIN scan_runs sr ON f.run_id = sr.run_id
                   WHERE f.category = ? AND sr.target_name != ?
                   ORDER BY f.confidence DESC LIMIT ?""",
                (category, exclude_target, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def count_findings_for_param(self, parameter_name: str) -> int:
        """Count findings for a parameter name."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM findings WHERE parameter_name = ?",
                (parameter_name,),
            )
            return int(cur.fetchone()[0])

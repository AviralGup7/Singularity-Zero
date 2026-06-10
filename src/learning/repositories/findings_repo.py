import logging
"""Findings repository - CRUD operations for findings table."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class FindingsRepo(BaseRepo):
    """Repository for findings table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            with self._cursor() as cur:
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_run_id_confidence ON findings(run_id, confidence DESC)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint_base)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)")
        except Exception as exc:
            logging.warning("Operation failed in findings_repo.py: %s", exc, exc_info=True)  # noqa: BLE001

    def record_finding(self, row: dict[str, Any]) -> None:
        """Record a finding."""
        expected_fields = [
            "finding_id", "run_id", "category", "title", "url", "severity",
            "confidence", "score", "decision", "lifecycle_state", "cvss_score",
            "plugin_name", "endpoint_base", "host", "parameter_name",
            "parameter_type", "evidence", "response_status", "response_body_hash",
            "tech_stack", "asset_id", "asset_type", "asset_criticality",
            "business_multiplier", "control_discount", "modern_risk_score",
            "remediation_priority", "triaged_at", "remediation_started_at",
            "fixed_at", "verified_at"
        ]
        params = {k: row.get(k) for k in expected_fields}
        if isinstance(params["tech_stack"], (list, set)):
            params["tech_stack"] = ",".join(list(params["tech_stack"]))

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_id, run_id, category, title, url, severity,
                    confidence, score, decision, lifecycle_state, cvss_score,
                    plugin_name, endpoint_base, host, parameter_name,
                    parameter_type, evidence, response_status, response_body_hash,
                    tech_stack, asset_id, asset_type, asset_criticality,
                    business_multiplier, control_discount, modern_risk_score,
                    remediation_priority, triaged_at, remediation_started_at,
                    fixed_at, verified_at)
                   VALUES (:finding_id, :run_id, :category, :title, :url, :severity,
                           :confidence, :score, :decision, :lifecycle_state, :cvss_score,
                           :plugin_name, :endpoint_base, :host, :parameter_name,
                           :parameter_type, :evidence, :response_status, :response_body_hash,
                           :tech_stack, :asset_id, :asset_type, :asset_criticality,
                           :business_multiplier, :control_discount, :modern_risk_score,
                           :remediation_priority, :triaged_at, :remediation_started_at,
                           :fixed_at, :verified_at)""",
                params,
            )

    def get_findings_for_run(self, run_id: str) -> list[dict]:
        """Get all findings for a run."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY confidence DESC",
                (run_id,),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_findings_for_runs(self, run_ids: list[str]) -> list[dict]:
        """Get all findings for multiple runs in a single query."""
        if not run_ids:
            return []
        placeholders_count = len(run_ids)
        placeholders = ",".join("?" for _ in range(placeholders_count))
        with self._cursor() as cur:
            cur.execute(
                f"SELECT * FROM findings WHERE run_id IN ({placeholders}) ORDER BY confidence DESC",  # noqa: S608  # nosec B608  (placeholders are static "?" chars)
                list(run_ids),
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
            # Bug #37 fix: ``tech_stack`` was previously accepted as a parameter
            # but never injected into the SQL query, so the function silently
            # ignored caller intent and returned findings for *any* tech
            # stack. We now build a parameterized IN clause for the tech
            # stack values and add it to the WHERE filter. We also OR-match
            # findings whose ``tech_stack`` is NULL because callers may not
            # have recorded one but still want to surface the historical
            # finding when its category/target pattern aligns.
            placeholders = ",".join("?" for _ in tech_stack)
            cur.execute(
                f"""SELECT f.*, sr.target_name
                    FROM findings f
                    JOIN scan_runs sr ON f.run_id = sr.run_id
                    WHERE f.category = ? AND sr.target_name != ?
                      AND (f.tech_stack IN ({placeholders}) OR f.tech_stack IS NULL OR f.tech_stack = '')
                    ORDER BY f.confidence DESC LIMIT ?""",  # noqa: S608  # nosec B608  (placeholders are static "?" chars)
                [category, exclude_target, *tech_stack, limit],
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

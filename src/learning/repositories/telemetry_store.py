"""Thin TelemetryStore facade that composes all repositories."""

from __future__ import annotations

import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, cast

from .attack_chains_repo import AttackChainsRepo
from .confidence_repo import ConfidenceRepo
from .feedback_repo import FeedbackRepo
from .findings_repo import FindingsRepo
from .fp_patterns_repo import FpPatternsRepo
from .graph_repo import GraphRepo
from .metrics_repo import MetricsRepo
from .scan_runs_repo import ScanRunsRepo
from .schema import _SCHEMA_DDL, apply_migrations
from .thresholds_repo import ThresholdsRepo

logger = logging.getLogger(__name__)


def _split_sql_statements(script: str) -> list[str]:
    """Split a multi-statement SQL script on top-level semicolons.

    ``sqlite3.Connection.executescript`` runs the script in a
    single implicit transaction, so a single bad statement
    (e.g. an old index pointing at a column that has been
    removed) aborts the entire script. The telemetry store
    wants to be tolerant of legacy databases that may carry
    such artifacts, so we split and run each statement
    individually.
    """
    statements: list[str] = []
    buf: list[str] = []
    for raw_line in script.splitlines():
        stripped = raw_line.strip()
        # Skip pure comment / empty lines from the buffer check
        # but keep them inside the current statement so the
        # parser sees the same source as ``executescript`` would.
        buf.append(raw_line)
        if stripped.endswith(";"):
            stmt = "\n".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
    tail = "\n".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


_KNOWN_TABLES = {
    "scan_runs",
    "findings",
    "feedback_events",
    "parameter_profiles",
    "fp_patterns",
    "risk_scores",
    "graph_nodes",
    "graph_edges",
    "threshold_history",
    "plugin_stats",
    "performance_metrics",
    "session_states",
    "attack_chains",
    "confidence_models",
    "assets",
    "risk_acceptances",
    "compensating_controls",
    "sla_events",
    "threat_intel_cache",
    "reviewer_actions",
}
_KNOWN_TIME_COLUMNS = {
    "created_at",
    "updated_at",
    "timestamp",
    "last_seen",
    "token_expiry",
    "expires_at",
    "detected_at",
    "recorded_at",
    "start_time",
    "end_time",
}

_DELETE_QUERIES = {  # noqa: S608  # nosec B608  (t and c are from hardcoded allowlisted sets)
    (t, c): f"DELETE FROM {t} WHERE {c} < ?"  # noqa: S608  # nosec B608
    for t in _KNOWN_TABLES
    for c in _KNOWN_TIME_COLUMNS
}

_COUNT_QUERIES = {  # noqa: S608  # nosec B608  (t is from hardcoded allowlisted set)
    t: f"SELECT COUNT(*) FROM {t}"  # noqa: S608  # nosec B608
    for t in _KNOWN_TABLES
}


import re

_SAFE_NAME_RE = re.compile(r"^[a-z_]+$")


def _safe_table(table: str) -> str:
    """Validate that a table name is in the known allowlist and matches safe pattern."""
    if not _SAFE_NAME_RE.match(table):
        raise ValueError(f"SQL injection guard: table name contains invalid characters: {table!r}")
    if table not in _KNOWN_TABLES:
        raise ValueError(f"SQL injection guard: unknown table name '{table}'")
    return table


def _safe_column(column: str) -> str:
    """Validate that a column name is in the known allowlist and matches safe pattern."""
    if not _SAFE_NAME_RE.match(column):
        raise ValueError(
            f"SQL injection guard: column name contains invalid characters: {column!r}"
        )
    if column not in _KNOWN_TIME_COLUMNS:
        raise ValueError(f"SQL injection guard: unknown column name '{column}'")
    return column


class TelemetryStore:
    """Thread-safe SQLite-backed telemetry persistence.

    Usage:
        store = TelemetryStore(".pipeline/telemetry.db")
        store.initialize()
        store.record_scan_run(...)
        store.insert_feedback_event(...)
        store.close()

    Or as context manager:
        with TelemetryStore(".pipeline/telemetry.db") as store:
            store.initialize()
            ...
    """

    def __init__(self, db_path: str | Path | None = None):
        """Initialize the telemetry store.

        Args:
            db_path: Path to the SQLite database file.
                     Defaults to .pipeline/telemetry.db in the working directory.
        """
        if db_path is None:
            db_path = Path(".pipeline") / "telemetry.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._initialized = False

        self.scan_runs = ScanRunsRepo(self.db_path, self._local)
        self.findings = FindingsRepo(self.db_path, self._local)
        self.feedback = FeedbackRepo(self.db_path, self._local)
        self.fp_patterns = FpPatternsRepo(self.db_path, self._local)
        self.graph = GraphRepo(self.db_path, self._local)
        self.thresholds = ThresholdsRepo(self.db_path, self._local)
        self.metrics = MetricsRepo(self.db_path, self._local)
        self.attack_chains = AttackChainsRepo(self.db_path, self._local)
        self.confidence = ConfidenceRepo(self.db_path, self._local)

    def _get_conn(self) -> Any:
        """Get a thread-local database connection."""
        return self.scan_runs._get_conn()

    def _ensure_connection(self) -> None:
        """Ensure a connection has been established."""
        self.scan_runs._ensure_connection()

    def initialize(self) -> None:
        """Create all tables and indexes if they don't exist.

        The order matters: column-level migrations are applied
        *before* the index-creation step, because some of the
        indexes reference columns that didn't exist on databases
        created before the modern risk domain. Running the schema
        script against such a database would otherwise fail on
        ``CREATE INDEX IF NOT EXISTS idx_findings_asset ON
        findings(asset_id)`` because the column is missing.

        Brand-new databases: ``CREATE TABLE IF NOT EXISTS`` already
        produces the modern schema, so the migration step is a
        no-op. Existing databases: the migration adds the missing
        columns, then the schema script recreates the indexes that
        depend on them.
        """
        if self._initialized:
            return
        conn = self._get_conn()
        # 1. Bring tables up to the modern shape (no-op on new DBs).
        try:
            added = apply_migrations(conn)
            if added:
                logger.info(
                    "Telemetry store: applied %d column migration(s) at %s",
                    added,
                    self.db_path,
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Telemetry store: migration step skipped: %s", exc)
        # 2. Run the full schema script (CREATE TABLE / CREATE INDEX).
        #    Each statement is wrapped in a try/except so a single
        #    bad statement (e.g. an old index pointing at a column
        #    that's been removed) doesn't poison the whole script.
        for raw_stmt in _split_sql_statements(_SCHEMA_DDL):
            if not raw_stmt.strip():
                continue
            try:
                conn.execute(raw_stmt)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Telemetry store: skipping schema statement (%s): %s",
                    exc,
                    raw_stmt.splitlines()[0][:80],
                )
        conn.commit()
        self._initialized = True
        logger.info("Telemetry store initialized at %s", self.db_path)

    def close(self) -> None:
        """Close the thread-local database connection.

        Callers must call this explicitly if not using the 'with' statement context manager
        to prevent resource and connection leaks.
        """
        if hasattr(self._local, "conn") and self._local.conn:
            try:
                self._local.conn.close()
            except sqlite3.ProgrammingError as exc:
                logger.warning("Operation failed in telemetry_store.py: %s", exc, exc_info=True)  # noqa: BLE001
            except Exception:  # noqa: S110
                pass
            self._local.conn = None

    def __enter__(self) -> TelemetryStore:
        self.initialize()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def record_scan_run(self, row: dict[str, Any]) -> None:
        """Record a scan run."""
        self.scan_runs.record_scan_run(row)

    def get_scan_run(self, run_id: str) -> dict | None:
        """Get a scan run by ID."""
        return self.scan_runs.get_scan_run(run_id)

    def get_recent_runs(self, target: str | None = None, limit: int = 20) -> list[dict]:
        """Get recent scan runs, optionally filtered by target."""
        return self.scan_runs.get_recent_runs(target, limit)

    def count_runs_for_target(self, target: str) -> int:
        """Count total runs for a target."""
        return self.scan_runs.count_runs_for_target(target)

    def record_finding(self, row: dict[str, Any]) -> None:
        """Record a finding."""
        self.findings.record_finding(row)

    def get_findings_for_run(self, run_id: str) -> list[dict]:
        """Get all findings for a run."""
        return self.findings.get_findings_for_run(run_id)

    def get_findings_for_runs(self, run_ids: list[str]) -> list[dict]:
        """Get all findings for multiple runs in a single query."""
        return self.findings.get_findings_for_runs(run_ids)

    def count_findings_for_target(self, target: str) -> int:
        """Count total findings for a target across all runs."""
        return self.findings.count_findings_for_target(target)

    def count_validated_findings_for_target(self, target: str) -> int:
        """Count validated findings for a target."""
        return self.findings.count_validated_findings_for_target(target)

    def insert_feedback_event(self, row: dict[str, Any]) -> None:
        """Insert a feedback event."""
        self.feedback.insert_feedback_event(row)

    def get_feedback_events_for_run(self, run_id: str) -> list[dict]:
        """Get feedback events for a run."""
        return self.feedback.get_feedback_events_for_run(run_id)

    def get_feedback_events_for_runs(self, run_ids: list[str]) -> list[dict]:
        """Get feedback events for multiple runs in a single query."""
        return self.feedback.get_feedback_events_for_runs(run_ids)

    def get_feedback_events(self, limit: int = 1000) -> list[dict]:
        """Get the most recent feedback events across all runs."""
        return self.feedback.get_feedback_events(limit)

    def get_feedback_events_for_endpoint(
        self, endpoint: str, host: str, limit: int = 50
    ) -> list[dict]:
        """Get feedback events for a specific endpoint."""
        return self.feedback.get_feedback_events_for_endpoint(endpoint, host, limit)

    def recompute_feedback_weights(self, run_id: str, decay_rate: float = 0.01) -> int:
        """Recompute feedback weights for events in a run.

        Returns the number of events updated.
        """
        return self.feedback.recompute_feedback_weights(run_id, decay_rate)

    def upsert_fp_pattern(self, row: dict[str, Any]) -> None:
        """Insert or update an FP pattern."""
        self.fp_patterns.upsert_fp_pattern(row)

    def upsert_fp_patterns(self, rows: list[dict[str, Any]]) -> None:
        """Insert or update multiple FP patterns in a single transaction."""
        self.fp_patterns.upsert_fp_patterns(rows)

    def get_fp_patterns(self, category: str | None = None, active_only: bool = True) -> list[dict]:
        """Get FP patterns, optionally filtered."""
        return self.fp_patterns.get_fp_patterns(category, active_only)

    def get_active_fp_pattern_count(self) -> int:
        """Count active FP patterns."""
        return self.fp_patterns.get_active_fp_pattern_count()

    def upsert_risk_score(self, row: dict[str, Any]) -> None:
        """Insert or update a risk score."""
        self.confidence.upsert_risk_score(row)

    def get_risk_scores_for_run(self, run_id: str) -> list[dict]:
        """Get risk scores for a run."""
        return self.confidence.get_risk_scores_for_run(run_id)

    def upsert_graph_node(self, row: dict[str, Any]) -> None:
        """Insert or update a graph node."""
        self.graph.upsert_graph_node(row)

    def upsert_graph_edge(self, row: dict[str, Any]) -> None:
        """Insert or update a graph edge."""
        self.graph.upsert_graph_edge(row)

    def get_graph_nodes(
        self, node_type: str | None = None, run_id: str | None = None
    ) -> list[dict]:
        """Get graph nodes with optional filters."""
        return self.graph.get_graph_nodes(node_type, run_id)

    def get_graph_edges(
        self,
        source_node_id: str | None = None,
        edge_type: str | None = None,
    ) -> list[dict]:
        """Get graph edges with optional filters."""
        return self.graph.get_graph_edges(source_node_id, edge_type)

    def record_threshold_history(self, row: dict[str, Any]) -> None:
        """Record a threshold calibration event."""
        self.thresholds.record_threshold_history(row)

    def get_threshold_history(
        self, run_id: str | None = None, category: str | None = None
    ) -> list[dict]:
        """Get threshold history."""
        return self.thresholds.get_threshold_history(run_id, category)

    def record_plugin_stat(self, row: dict[str, Any]) -> None:
        """Record plugin execution statistics."""
        self.metrics.record_plugin_stat(row)

    def get_plugin_stats(self, run_id: str | None = None) -> list[dict]:
        """Get plugin statistics."""
        return self.metrics.get_plugin_stats(run_id)

    def get_plugin_stats_for_runs(self, run_ids: list[str]) -> list[dict]:
        """Get plugin statistics for multiple runs in a single query."""
        return self.metrics.get_plugin_stats_for_runs(run_ids)

    def record_metric(
        self, run_id: str, name: str, value: float, category: str | None = None
    ) -> None:
        """Record a performance metric."""
        self.metrics.record_metric(run_id, name, value, category)

    def get_metrics_for_run(self, run_id: str) -> list[dict]:
        """Get all metrics for a run."""
        return self.metrics.get_metrics_for_run(run_id)

    def record_attack_chain(self, row: dict[str, Any]) -> None:
        """Record a detected attack chain."""
        self.attack_chains.record_attack_chain(row)

    def get_attack_chains(
        self,
        pattern_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get attack chains with optional filters."""
        return self.attack_chains.get_attack_chains(pattern_name, status, limit)

    def get_attack_chains_for_finding(self, finding_id: str) -> list[dict]:
        """Get all attack chains containing a specific finding ID."""
        return self.attack_chains.get_attack_chains_for_finding(finding_id)

    def save_confidence_model(self, row: dict[str, Any]) -> None:
        """Save a confidence calibration model."""
        self.confidence.save_confidence_model(row)

    def get_confidence_model(self, category: str, plugin_name: str) -> dict | None:
        """Get a confidence model for a category/plugin pair."""
        return self.confidence.get_confidence_model(category, plugin_name)

    def get_fp_rate_for_pattern(self, category: str, plugin: str) -> float:
        """Get the historical FP rate for a category/plugin pattern."""
        return self.feedback.get_fp_rate_for_pattern(category, plugin)

    def get_confidence_distribution(self, category: str) -> list[float]:
        """Get the distribution of confidence scores for a category."""
        return self.feedback.get_confidence_distribution(category)

    def get_parameter_profile(
        self, parameter_name: str, endpoint: str | None = None
    ) -> dict | None:
        """Get a parameter profile."""
        conn = self._get_conn()
        cur = conn.cursor()
        if endpoint:
            cur.execute(
                "SELECT * FROM parameter_profiles WHERE parameter_name = ? AND endpoint_context = ?",
                (parameter_name, endpoint),
            )
        else:
            cur.execute(
                "SELECT * FROM parameter_profiles WHERE parameter_name = ? ORDER BY historical_findings DESC LIMIT 1",
                (parameter_name,),
            )
        row = cur.fetchone()
        return dict(row) if row else None

    def count_findings_for_param(self, parameter_name: str) -> int:
        """Count findings for a parameter name."""
        return self.findings.count_findings_for_param(parameter_name)

    def get_fp_rate_for_param(self, parameter_name: str) -> float:
        """Get the FP rate for a parameter name."""
        return self.feedback.get_fp_rate_for_param(parameter_name)

    def find_previous_findings(
        self,
        endpoint: str,
        category: str,
        exclude_run: str,
        limit: int = 5,
    ) -> list[dict]:
        """Find previous findings matching an endpoint and category."""
        return self.findings.find_previous_findings(endpoint, category, exclude_run, limit)

    def find_cross_target_findings(
        self,
        tech_stack: list[str],
        category: str,
        exclude_target: str,
        limit: int = 3,
    ) -> list[dict]:
        """Find findings on other targets with matching tech stack and category."""
        return self.findings.find_cross_target_findings(tech_stack, category, exclude_target, limit)

    _KNOWN_TABLES = _KNOWN_TABLES
    _KNOWN_TIME_COLUMNS = _KNOWN_TIME_COLUMNS
    _DELETE_QUERIES = _DELETE_QUERIES
    _COUNT_QUERIES = _COUNT_QUERIES

    @staticmethod
    def _validate_schema(table: str, column: str) -> None:
        if table not in TelemetryStore._KNOWN_TABLES:
            raise ValueError(f"Unknown table: {table!r}")
        if column not in TelemetryStore._KNOWN_TIME_COLUMNS:
            raise ValueError(f"Invalid column: {column!r}")

    def execute_query(self, query: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Execute a SELECT query and return results as list of dicts.

        This is a public method that avoids exposing the raw connection
        to external callers like routers.
        """
        conn = self._get_conn()
        cur = conn.execute(query, params or [])
        columns = [desc[0] for desc in cur.description] if cur.description else []
        return [dict(zip(columns, row)) for row in cur.fetchall()]

    def execute_write(self, query: str, params: list[Any] | None = None) -> int:
        """Execute a write query (INSERT/UPDATE/DELETE) and return rowcount.

        This is a public method that avoids exposing the raw connection
        to external callers like routers.
        """
        conn = self._get_conn()
        cur = conn.execute(query, params or [])
        conn.commit()
        return int(cur.rowcount or 0)

    def execute_write_many(self, query: str, params_list: list[list[Any]]) -> int:
        """Execute a write query with multiple parameter sets in one transaction.

        Returns total rowcount across all executions.
        """
        conn = self._get_conn()
        total = 0
        for params in params_list:
            cur = conn.execute(query, params)
            total += cur.rowcount
        conn.commit()
        return total

    def delete_expired_records(self, table: str, cutoff: str, column: str = "created_at") -> int:
        """Delete records older than cutoff. Returns count deleted."""
        query = self._DELETE_QUERIES.get((table, column))
        if not query:
            raise ValueError(f"Invalid table or column for expiration check: {table}.{column}")
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            query,
            (cutoff,),
        )
        conn.commit()
        return cast(int, cur.rowcount)

    def get_db_size(self) -> dict[str, int]:
        """Get database size information."""
        conn = self._get_conn()
        cur = conn.cursor()
        tables = [
            "scan_runs",
            "findings",
            "feedback_events",
            "parameter_profiles",
            "fp_patterns",
            "risk_scores",
            "graph_nodes",
            "graph_edges",
            "threshold_history",
            "plugin_stats",
            "performance_metrics",
            "session_states",
            "attack_chains",
            "confidence_models",
        ]
        sizes = {}
        for table in tables:
            query = self._COUNT_QUERIES.get(table)
            if not query:
                raise ValueError(f"Invalid table name: {table}")
            cur.execute(query)
            sizes[table] = int(cur.fetchone()[0])
        return sizes

    def run_maintenance(self, retention_policies: dict[str, int] | None = None) -> dict[str, Any]:
        """Run database maintenance.

        This automatically deletes expired records based on retention policies,
        then performs VACUUM and ANALYZE.

        Args:
            retention_policies: Dict mapping table name to retention age in days.
                                If None, defaults are applied:
                                - "feedback_events": 90 days
                                - "performance_metrics": 30 days
                                - "plugin_stats": 30 days
                                - "threshold_history": 60 days
        """
        import datetime

        now = datetime.datetime.now(datetime.UTC)
        deleted_counts = {}

        # 1. Absolute expiration cleanup (delete where expiry < now)
        try:
            now_iso = now.isoformat()
            deleted_counts["session_states"] = self.delete_expired_records(
                "session_states", now_iso, "token_expiry"
            )
            deleted_counts["threat_intel_cache"] = self.delete_expired_records(
                "threat_intel_cache", now_iso, "expires_at"
            )
        except Exception as exc:
            logger.warning("Telemetry store maintenance: failed absolute expiry cleanup: %s", exc)

        # 2. Relative retention cleanup (delete where age > X days)
        policies = retention_policies or {
            "feedback_events": 90,
            "performance_metrics": 30,
            "plugin_stats": 30,
            "threshold_history": 60,
        }

        for table, days in policies.items():
            try:
                cutoff = (now - datetime.timedelta(days=days)).isoformat()
                column = "timestamp" if table == "feedback_events" else "recorded_at"
                deleted_counts[table] = self.delete_expired_records(table, cutoff, column)
            except Exception as exc:
                logger.warning(
                    "Telemetry store maintenance: failed to prune table %s: %s", table, exc
                )

        # 3. Compact & optimize
        conn = self._get_conn()
        try:
            conn.execute("VACUUM")
        except sqlite3.OperationalError as exc:
            logger.warning(
                "Telemetry store maintenance: VACUUM failed (may be SQLITE_FULL or SQLITE_BUSY): %s",
                exc,
            )
        conn.execute("ANALYZE")
        return {
            "status": "completed",
            "deleted_counts": deleted_counts,
            "size": self.get_db_size(),
        }

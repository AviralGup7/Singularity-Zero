"""Thin TelemetryStore facade that composes all repositories."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from .attack_chains_repo import AttackChainsRepo
from .confidence_repo import ConfidenceRepo
from .feedback_repo import FeedbackRepo
from .findings_repo import FindingsRepo
from .fp_patterns_repo import FpPatternsRepo
from .graph_repo import GraphRepo
from .metrics_repo import MetricsRepo
from .scan_runs_repo import ScanRunsRepo
from .schema import _SCHEMA_DDL
from .thresholds_repo import ThresholdsRepo

logger = logging.getLogger(__name__)


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
        """Create all tables and indexes if they don't exist."""
        if self._initialized:
            return
        conn = self._get_conn()
        conn.executescript(_SCHEMA_DDL)
        self._initialized = True
        logger.info("Telemetry store initialized at %s", self.db_path)

    def close(self) -> None:
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def __enter__(self) -> TelemetryStore:
        self.initialize()
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self) -> None:
        """Best-effort connection cleanup when store is garbage collected."""
        try:
            self.close()
        except Exception:
            pass

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
    }
    _KNOWN_TIME_COLUMNS = {"created_at", "updated_at", "timestamp", "last_seen"}

    @staticmethod
    def _validate_schema(table: str, column: str) -> None:
        if table not in TelemetryStore._KNOWN_TABLES:
            raise ValueError(f"Unknown table: {table!r}")
        if column not in TelemetryStore._KNOWN_TIME_COLUMNS:
            raise ValueError(f"Invalid column: {column!r}")

    def delete_expired_records(self, table: str, cutoff: str, column: str = "created_at") -> int:
        """Delete records older than cutoff. Returns count deleted."""
        self._validate_schema(table, column)
        conn = self._get_conn()
        cur = conn.cursor()
        query = f"DELETE FROM {table} WHERE {column} < ?"
        cur.execute(
            query,
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount

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
            if table not in self._KNOWN_TABLES:
                raise ValueError(f"Invalid table name: {table}")
            cur.execute('SELECT COUNT(*) FROM ' + table)
            sizes[table] = int(cur.fetchone()[0])
        return sizes

    def run_maintenance(self) -> dict[str, Any]:
        """Run database maintenance (VACUUM, ANALYZE)."""
        conn = self._get_conn()
        conn.execute("VACUUM")
        conn.execute("ANALYZE")
        return {"status": "completed", "size": self.get_db_size()}

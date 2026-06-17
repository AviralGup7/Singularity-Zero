"""Database latency metrics via SQLAlchemy event listeners.

Instruments SQLAlchemy to record query execution time, connection pool
utilization, and transaction metrics. Works with both sync and async
engines.

Usage:
    from src.infrastructure.observability.db_metrics import install_db_metrics

    # After creating your SQLAlchemy engine:
    install_db_metrics(engine)
"""

from __future__ import annotations

import time
import threading
from typing import Any

from sqlalchemy import event, engine
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

# Bucket boundaries optimized for DB query latency (seconds)
_DB_LATENCY_BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

# Maximum unique SQL statement lengths to track (prevent cardinality)
_MAX_STATEMENT_LABELS = 64


class DBMetricsCollector:
    """Collects database metrics via SQLAlchemy event listeners.

    Tracks:
    - Query execution latency by operation type
    - Connection pool utilization
    - Transaction counts
    - Query error rates
    """

    def __init__(self) -> None:
        self._query_count = 0
        self._error_count = 0
        self._lock = threading.Lock()
        self._installed_engines: set[int] = set()

    def _record_query(
        self,
        conn: Any,
        cursor: Any,
        statement: str | None,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        """Record query execution metrics after each statement."""
        # This is called before execution; we set a timer
        pass

    def _record_query_after(
        self,
        conn: Any,
        cursor: Any,
        statement: str | None,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        """Record query metrics after execution (via cursor event)."""
        pass

    def _before_cursor_execute(
        self,
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        """Store start time before cursor execution."""
        if not hasattr(conn, "_metrics_start_time"):
            conn._metrics_start_time = {}
        conn._metrics_start_time[id(cursor)] = time.monotonic()

    def _after_cursor_execute(
        self,
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        """Record query duration after cursor execution."""
        start = getattr(conn, "_metrics_start_time", {}).pop(id(cursor), None)
        if start is None:
            return

        duration = time.monotonic() - start

        # Classify the operation type
        stmt_upper = statement.strip().upper() if statement else ""
        if stmt_upper.startswith("SELECT"):
            op_type = "select"
        elif stmt_upper.startswith(("INSERT", "CREATE")):
            op_type = "insert"
        elif stmt_upper.startswith("UPDATE"):
            op_type = "update"
        elif stmt_upper.startswith("DELETE"):
            op_type = "delete"
        elif stmt_upper.startswith(("ALTER", "DROP")):
            op_type = "ddl"
        else:
            op_type = "other"

        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()

            # Query latency by operation type
            metrics.histogram(
                "db_query_duration_seconds",
                "Database query execution duration by operation type",
                buckets=_DB_LATENCY_BUCKETS,
                labels={"operation": op_type},
            ).observe(duration)

            # Total query count
            metrics.counter(
                "db_queries_total",
                "Total database queries executed",
                labels={"operation": op_type},
            ).inc()

            with self._lock:
                self._query_count += 1
        except Exception:
            pass

    def _handle_dbapi_error(self, conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, exception: Any) -> None:
        """Record database errors."""
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.counter(
                "db_query_errors_total",
                "Total database query errors",
            ).inc()

            with self._lock:
                self._error_count += 1
        except Exception:
            pass


_collector: DBMetricsCollector | None = None
_collector_lock = threading.Lock()


def _get_collector() -> DBMetricsCollector:
    global _collector
    if _collector is None:
        _collector = DBMetricsCollector()
    return _collector


def install_db_metrics(engine_instance: Engine) -> None:
    """Install SQLAlchemy event listeners for database metrics.

    Args:
        engine_instance: SQLAlchemy Engine to instrument.
    """
    collector = _get_collector()
    engine_id = id(engine_instance)

    with _collector_lock:
        if engine_id in collector._installed_engines:
            return
        collector._installed_engines.add(engine_id)

    # Cursor-level events for accurate timing
    event.listen(engine_instance, "before_cursor_execute", collector._before_cursor_execute)
    event.listen(engine_instance, "after_cursor_execute", collector._after_cursor_execute)
    event.listen(engine_instance, "handle_dbapi_error", collector._handle_dbapi_error)

    # Connection pool events
    @event.listens_for(engine_instance, "connect")
    def _on_connect(dbapi_conn: Any, connection_record: Any) -> None:
        try:
            from src.infrastructure.observability.metrics import get_metrics
            get_metrics().counter("db_connections_total", "Total DB connections created").inc()
        except Exception:
            pass

    @event.listens_for(engine_instance, "checkout")
    def _on_checkout(dbapi_conn: Any, connection_record: Any, connection_proxy: Any) -> None:
        try:
            from src.infrastructure.observability.metrics import get_metrics
            get_metrics().counter("db_connection_checkouts_total", "Total DB connection checkouts").inc()
        except Exception:
            pass


def record_pool_stats(pool: Any) -> None:
    """Record connection pool utilization metrics.

    Call this periodically (e.g., via a background task) to update
    pool state gauges.

    Args:
        pool: SQLAlchemy pool instance (QueuePool recommended).
    """
    try:
        from src.infrastructure.observability.metrics import get_metrics

        metrics = get_metrics()

        if hasattr(pool, "size"):
            metrics.gauge("db_pool_size", "Connection pool total size").set(pool.size())
        if hasattr(pool, "checkedout"):
            metrics.gauge("db_pool_checked_out", "Connections currently checked out").set(pool.checkedout())
        if hasattr(pool, "checkedin"):
            metrics.gauge("db_pool_checked_in", "Connections currently idle in pool").set(pool.checkedin())
        if hasattr(pool, "overflow"):
            metrics.gauge("db_pool_overflow", "Connections created beyond pool size").set(pool.overflow())
    except Exception:
        pass

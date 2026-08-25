"""Persistent job store backed by SQLite.

Provides durable storage of job records so they survive dashboard restarts.
Jobs are written to SQLite on state transitions and loaded back on startup.

Bug #33: Uses canonical src.core.lifecycle import instead of
src.infrastructure.lifecycle re-export to prevent split-brain if the
re-export path is ever removed.

Bug #34: Connection cleanup uses explicit close() instead of relying
on __del__ GC timing. A weakref.finalize callback provides a safety
net, but the primary cleanup path is the lifecycle-registered close().
"""

import json
import logging
import sqlite3
import threading
import time
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from src.dashboard.job_status import JobStatus, _transition
from src.infrastructure.db.sqlite_utils import (
    SQLITE_BUSY_TIMEOUT_MS as _BUSY_TIMEOUT_MS,
)
from src.infrastructure.db.sqlite_utils import (
    SQLITE_CONNECT_TIMEOUT_SECONDS as _CONNECT_TIMEOUT_SECONDS,
)
from src.infrastructure.db.sqlite_utils import (
    SQLITE_LOCK_RETRY_ATTEMPTS as _LOCK_RETRY_ATTEMPTS,
)
from src.infrastructure.db.sqlite_utils import (
    SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS as _LOCK_RETRY_BASE_DELAY_SECONDS,
)
from src.infrastructure.db.sqlite_utils import (
    safe_close,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_updated ON jobs(updated_at);
"""


def _json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_compatible(item) for item in value]

    pid = getattr(value, "pid", None)
    if isinstance(pid, int):
        return {"type": value.__class__.__name__, "pid": pid}

    return repr(value)


def _prepare_job_for_storage(job: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {str(key): value for key, value in dict(job).items()}

    runtime_process = payload.get("process")
    if runtime_process is not None:
        pid = getattr(runtime_process, "pid", None)
        if isinstance(pid, int):
            payload["process_pid"] = pid

    # Runtime process handles are in-memory only and should never be persisted.
    payload["process"] = None
    return cast(dict[str, Any], _json_compatible(payload))


class _ConnWrapper:
    """Bug #34: Wrapper uses weakref.finalize instead of __del__ for
    deterministic connection cleanup when the wrapper is GC'd.

    The __del__ method is unreliable — Python does not guarantee when
    (or even if) __del__ runs, especially under reference cycles or
    interpreter shutdown. weakref.finalize provides a more deterministic
    cleanup path.
    """

    def __init__(
        self, conn: sqlite3.Connection, on_close: Callable[[sqlite3.Connection], None]
    ) -> None:
        self.conn = conn
        self.on_close = on_close
        # Bug #34: weakref.finalize runs when this object is garbage collected,
        # providing a safety net beyond the explicit close() path.
        self._finalizer = weakref.finalize(self, _ConnWrapper._cleanup, conn, on_close)

    @staticmethod
    def _cleanup(conn: sqlite3.Connection, on_close: Callable[[sqlite3.Connection], None]) -> None:
        try:
            on_close(conn)
        except Exception:
            logger.warning("Operation failed in job_store.py", exc_info=True)

    def close(self) -> None:
        """Explicitly close the connection — preferred over relying on GC."""
        if self._finalizer.detach():
            try:
                self.on_close(self.conn)
            except Exception:
                logger.warning("Operation failed in job_store.py", exc_info=True)


class JobStore:
    """SQLite-backed persistent store for job records."""

    _MAX_CONNECTION_LIFETIME_SECONDS = 300.0  # 5 minutes

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        self._all_connections: list[sqlite3.Connection] = []  # Track all created connections
        self._conn_created_at: dict[int, float] = {}  # conn id -> monotonic time
        self._init_db()
        self._register_with_lifecycle()

    def _register_with_lifecycle(self) -> None:
        """Bug #33: Uses canonical core.lifecycle import."""
        try:
            from src.core.lifecycle import get_lifecycle_manager

            get_lifecycle_manager().register_shutdown(
                f"job_store_{id(self)}",
                self.close,
                after=["http_safety_session"],
            )
        except ImportError:
            logger.warning("Operation failed in job_store.py", exc_info=True)

    def _get_conn(self) -> sqlite3.Connection:
        wrapper = getattr(self._local, "wrapper", None)
        # Check if existing connection is too old (fix #42: max lifetime)
        if wrapper is not None and wrapper.conn is not None:
            conn_id = id(wrapper.conn)
            created = self._conn_created_at.get(conn_id, 0.0)
            if (time.monotonic() - created) > self._MAX_CONNECTION_LIFETIME_SECONDS:
                self._drop_thread_conn()
                wrapper = None
        if wrapper is None or wrapper.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=_CONNECT_TIMEOUT_SECONDS,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA foreign_keys=ON")
            except Exception:
                try:
                    conn.close()
                except sqlite3.ProgrammingError as exc:
                    logger.warning("Operation failed in job_store.py: %s", exc, exc_info=True)  # noqa: BLE001
                raise

            def _remove_conn(c: sqlite3.Connection) -> None:
                try:
                    c.close()
                except Exception:
                    logger.warning("Operation failed in job_store.py", exc_info=True)
                with self._lock:
                    if c in self._all_connections:
                        self._all_connections.remove(c)
                    self._conn_created_at.pop(id(c), None)

            self._local.wrapper = _ConnWrapper(conn, _remove_conn)
            self._local._conn = conn
            with self._lock:
                self._all_connections.append(conn)
                self._conn_created_at[id(conn)] = time.monotonic()
        return cast(sqlite3.Connection, self._local.wrapper.conn)

    @staticmethod
    def _is_locked_error(exc: BaseException) -> bool:
        return (
            "database is locked" in str(exc).lower()
            or "database table is locked" in str(exc).lower()
        )

    def _drop_thread_conn(self) -> None:
        wrapper = getattr(self._local, "wrapper", None)
        if wrapper is None:
            return
        conn = wrapper.conn
        if conn is None:
            return
        try:
            safe_close(conn)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to close failed SQLite connection: %s", exc)
        finally:
            with self._lock:
                if conn in self._all_connections:
                    self._all_connections.remove(conn)
                self._conn_created_at.pop(id(conn), None)
            self._local.wrapper = None
            self._local._conn = None

    def _with_retry(self, operation: Callable[[sqlite3.Connection], Any]) -> Any:
        """Execute *operation* with retry on SQLite lock errors.

        Includes a max total retry time to prevent indefinite blocking of
        the caller thread (fix #41).  If the total time exceeds the limit,
        the last error is raised immediately.
        """
        _MAX_TOTAL_RETRY_SECONDS = 2.0
        last_exc: sqlite3.OperationalError | None = None
        total_start = time.monotonic()
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            conn = self._get_conn()
            try:
                return operation(conn)
            except sqlite3.OperationalError as exc:
                last_exc = exc
                try:
                    conn.rollback()
                except sqlite3.Error as rollback_exc:
                    logger.warning(
                        "Operation failed in job_store.py: %s", rollback_exc, exc_info=True
                    )  # noqa: BLE001
                self._drop_thread_conn()
                if not self._is_locked_error(exc) or attempt == _LOCK_RETRY_ATTEMPTS - 1:
                    raise
                elapsed = time.monotonic() - total_start
                if elapsed >= _MAX_TOTAL_RETRY_SECONDS:
                    logger.warning(
                        "JobStore retry: exceeded %.1fs total retry time, giving up",
                        _MAX_TOTAL_RETRY_SECONDS,
                    )
                    raise
                time.sleep(_LOCK_RETRY_BASE_DELAY_SECONDS * (2**attempt))
            except Exception:
                try:
                    conn.rollback()
                except sqlite3.Error as exc:
                    logger.warning("Operation failed in job_store.py: %s", exc, exc_info=True)  # noqa: BLE001
                raise
        if last_exc is not None:
            raise last_exc
        return None

    def _init_db(self) -> None:
        with self._lock:

            def _op(conn: sqlite3.Connection) -> None:
                conn.executescript(_SCHEMA)
                conn.commit()

            self._with_retry(_op)

    def close(self) -> None:
        """Close all database connections created across all threads."""
        with self._lock:
            for conn in self._all_connections:
                try:
                    safe_close(conn)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to close SQLite connection cleanly: %s", exc)
            self._all_connections.clear()
            self._conn_created_at.clear()
            self._local.wrapper = None
            self._local._conn = None

    def save(self, job: dict[str, Any]) -> None:
        """Upsert a job record."""

        def _op(conn: sqlite3.Connection) -> None:
            persisted_job = _prepare_job_for_storage(job)
            conn.execute(
                """INSERT INTO jobs (job_id, data, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(job_id) DO UPDATE SET
                       data=excluded.data,
                       status=excluded.status,
                       updated_at=excluded.updated_at""",
                (
                    job["id"],
                    json.dumps(persisted_job),
                    job.get("status", "unknown"),
                    job.get("started_at", time.time()),
                    time.time(),
                ),
            )
            conn.commit()

        self._with_retry(_op)

    def load_all(self) -> dict[str, dict[str, Any]]:
        """Load all jobs, returning a dict keyed by job_id."""
        import logging as _logging

        try:
            rows = self._with_retry(
                lambda conn: conn.execute(
                    "SELECT data FROM jobs ORDER BY created_at DESC"
                ).fetchall()
            )
            result: dict[str, dict[str, Any]] = {}
            for row in rows:
                try:
                    job = json.loads(row["data"])
                    result[job["id"]] = job
                except (json.JSONDecodeError, TypeError, KeyError) as exc:
                    logger.debug("Failed to decode job data from row: %s", exc)
                    continue
            _logging.getLogger(__name__).info(
                "LOADED jobs from persistence: keys=%s count=%d",
                list(result.keys()),
                len(result),
            )
            return result
        except Exception:
            logger.exception("Failed to load jobs")
            return {}

    def load_active(self) -> dict[str, dict[str, Any]]:
        """Load only jobs that were running (need restart/recovery)."""
        try:
            rows = self._with_retry(
                lambda conn: conn.execute(
                    "SELECT data FROM jobs WHERE status IN (?, ?, ?) ORDER BY created_at DESC",
                    ("running", "starting", "stopping"),
                ).fetchall()
            )
            result: dict[str, dict[str, Any]] = {}
            for row in rows:
                try:
                    job = json.loads(row["data"])
                    result[job["id"]] = job
                except (json.JSONDecodeError, TypeError, KeyError) as exc:
                    logger.debug("Failed to decode job data from row: %s", exc)
                    continue
            return result
        except Exception:
            logger.exception("Failed to load active jobs")
            return {}

    def mark_stale_running(self) -> int:
        """Mark any remaining 'running' jobs as 'failed' (dashboard restarted).

        Returns the number of jobs marked as stale.
        """
        stale_ids: list[str] = []
        try:

            def _op(conn: sqlite3.Connection) -> None:
                rows = conn.execute(
                    "SELECT data FROM jobs WHERE status IN (?, ?, ?)",
                    ("running", "starting", "stopping"),
                ).fetchall()
                for row in rows:
                    try:
                        job = json.loads(row["data"])
                        _transition(job, JobStatus.FAILED)
                        job["error"] = "Dashboard restarted while job was running"
                        job["status_message"] = "Job was interrupted by dashboard restart"
                        if "process_pid" in job:
                            del job["process_pid"]
                        job["finished_at"] = time.time()
                        job["updated_at"] = job["finished_at"]
                        conn.execute(
                            """UPDATE jobs SET data=?, status=?, updated_at=?
                               WHERE job_id=?""",
                            (
                                json.dumps(job),
                                "failed",
                                job["finished_at"],
                                job["id"],
                            ),
                        )
                        stale_ids.append(job["id"])
                    except (json.JSONDecodeError, TypeError, KeyError) as exc:
                        logger.debug("Failed to decode job data from row: %s", exc)
                        continue
                conn.commit()

            self._with_retry(_op)
        except Exception:
            logger.exception("Failed to mark stale jobs")
        return len(stale_ids)

    def cleanup_old(self, max_age_days: int = 30) -> int:
        """Delete jobs older than max_age_days. Returns count deleted."""
        cutoff = time.time() - (max_age_days * 86400)
        try:

            def _op(conn: sqlite3.Connection) -> int:
                cursor = conn.execute(
                    "DELETE FROM jobs WHERE updated_at < ?",
                    (cutoff,),
                )
                conn.commit()
                return int(cursor.rowcount)

            return int(self._with_retry(_op))
        except Exception:
            logger.exception("Failed to clean up old jobs")
            return 0

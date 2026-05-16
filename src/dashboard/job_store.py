"""Persistent job store backed by SQLite.

Provides durable storage of job records so they survive dashboard restarts.
Jobs are written to SQLite on state transitions and loaded back on startup.
"""

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, cast

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


class JobStore:
    """SQLite-backed persistent store for job records."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "_conn") or self._local._conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local._conn = conn
        return cast(sqlite3.Connection, self._local._conn)

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.executescript(_SCHEMA)
            conn.commit()

    def close(self) -> None:
        """Close the database connection for the current thread."""
        if hasattr(self._local, "_conn") and self._local._conn is not None:
            try:
                self._local._conn.close()
            except Exception:  # noqa: S110
                pass
            self._local._conn = None

    def save(self, job: dict[str, Any]) -> None:
        """Upsert a job record."""
        with self._lock:
            conn = self._get_conn()
            try:
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
            except Exception:  # noqa: S110
                logger.exception("Failed to save job %s", job.get("id"))
                conn.rollback()

    def load_all(self) -> dict[str, dict[str, Any]]:
        """Load all jobs, returning a dict keyed by job_id."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT data FROM jobs ORDER BY created_at DESC").fetchall()
                result: dict[str, dict[str, Any]] = {}
                for row in rows:
                    try:
                        job = json.loads(row["data"])
                        result[job["id"]] = job
                    except (json.JSONDecodeError, KeyError):
                        continue
                return result
            except Exception:  # noqa: S110
                logger.exception("Failed to load jobs")
                return {}

    def load_active(self) -> dict[str, dict[str, Any]]:
        """Load only jobs that were running (need restart/recovery)."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT data FROM jobs WHERE status = ? ORDER BY created_at DESC",
                    ("running",),
                ).fetchall()
                result: dict[str, dict[str, Any]] = {}
                for row in rows:
                    try:
                        job = json.loads(row["data"])
                        result[job["id"]] = job
                    except (json.JSONDecodeError, KeyError):
                        continue
                return result
            except Exception:  # noqa: S110
                logger.exception("Failed to load active jobs")
                return {}

    def mark_stale_running(self) -> int:
        """Mark any remaining 'running' jobs as 'failed' (dashboard restarted).

        Returns the number of jobs marked as stale.
        """
        stale_ids: list[str] = []
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT data FROM jobs WHERE status = ?",
                    ("running",),
                ).fetchall()
                for row in rows:
                    try:
                        job = json.loads(row["data"])
                        job["status"] = "failed"
                        job["error"] = "Dashboard restarted while job was running"
                        job["status_message"] = "Job was interrupted by dashboard restart"
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
                    except (json.JSONDecodeError, KeyError):
                        continue
                conn.commit()
            except Exception:  # noqa: S110
                logger.exception("Failed to mark stale jobs")
                conn.rollback()
        return len(stale_ids)

    def cleanup_old(self, max_age_days: int = 30) -> int:
        """Delete jobs older than max_age_days. Returns count deleted."""
        cutoff = time.time() - (max_age_days * 86400)
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM jobs WHERE updated_at < ?",
                    (cutoff,),
                )
                conn.commit()
                return cursor.rowcount
            except Exception:  # noqa: S110
                logger.exception("Failed to clean up old jobs")
                conn.rollback()
                return 0

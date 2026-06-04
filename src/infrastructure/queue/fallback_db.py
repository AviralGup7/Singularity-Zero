"""SQLite-backed fallback store data access layer for RedisClient.

Encapsulates data storage, retrieval, deletion, and schema management
used when the main Redis instance is unavailable.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
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

logger = get_pipeline_logger(__name__)


class FallbackDB:
    """Manages SQLite access for the in-memory/disk fallback storage."""

    def __init__(self, db_path: str) -> None:
        """Initialize fallback database.

        Args:
            db_path: Absolute or relative path to the SQLite DB file.
        """
        self.db_path = db_path
        self._thread_local = threading.local()
        self._lock = threading.RLock()
        self._available = False
        self.last_error: str | None = None
        self._init_sqlite()

    @staticmethod
    def _is_locked_error(exc: BaseException) -> bool:
        message = str(exc).lower()
        return "database is locked" in message or "database table is locked" in message

    def _configure_conn(self, conn: sqlite3.Connection, *, read_only: bool = False) -> None:
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys=ON")
        if not read_only:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

    def _with_retry(self, operation: Callable[[], Any], *, write: bool = False) -> Any:
        last_exc: Exception | None = None
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            try:
                return operation()
            except sqlite3.OperationalError as exc:
                last_exc = exc
                self.last_error = str(exc)
                self.close()
                if not self._is_locked_error(exc) or attempt == _LOCK_RETRY_ATTEMPTS - 1:
                    if write:
                        self._thread_local.read_only = True
                    raise
                time.sleep(_LOCK_RETRY_BASE_DELAY_SECONDS * (2**attempt))
        if last_exc is not None:
            raise last_exc
        return None

    def _init_sqlite(self) -> None:
        """Initialize the SQLite fallback database schema."""
        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=_CONNECT_TIMEOUT_SECONDS)
            try:
                self._configure_conn(conn)
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS fallback_store (
                        key TEXT PRIMARY KEY,
                        type TEXT,
                        value TEXT
                    )
                    """
                )
                conn.commit()
                self._available = True
                self.last_error = None
            finally:
                conn.close()
        except Exception as exc:
            self._available = False
            self.last_error = str(exc)
            logger.error("Failed to initialize SQLite fallback database: %s", exc)

    def _get_sqlite_conn(self) -> Any:
        if not self._available or getattr(self._thread_local, "read_only", False):
            self._init_sqlite()
        if not self._available:
            raise RuntimeError(f"SQLite fallback database unavailable: {self.last_error}")
        if not hasattr(self._thread_local, "conn") or self._thread_local.conn is None:
            read_only = getattr(self._thread_local, "read_only", False)
            uri = f"file:{self.db_path}?mode=ro" if read_only else self.db_path
            conn = sqlite3.connect(
                uri,
                timeout=_CONNECT_TIMEOUT_SECONDS,
                uri=read_only,
            )
            self._thread_local.conn = conn
            self._configure_conn(conn, read_only=read_only)
        return self._thread_local.conn

    def close(self) -> None:
        """Close the cached database connection for the current thread."""
        conn = getattr(self._thread_local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: S110
                pass
            self._thread_local.conn = None

    def db_get(self, key: str) -> tuple[str | None, Any]:
        """Get key type and raw Python data from SQLite."""
        try:

            def _op() -> Any:
                conn = self._get_sqlite_conn()
                return conn.execute(
                    "SELECT type, value FROM fallback_store WHERE key = ?", (key,)
                ).fetchone()

            row = self._with_retry(_op)
            if row is None:
                return None, None

            val_type = row["type"]
            val_raw = row["value"]
            if val_raw is None:
                return val_type, None

            data = json.loads(val_raw)
            if val_type == "set":
                return val_type, set(data)
            return val_type, data
        except Exception as exc:
            logger.error("SQLite fallback get error for key '%s': %s", key, exc)
            return None, None

    def db_set(self, key: str, val_type: str, data: Any) -> None:
        """Save key type and raw Python data to SQLite."""
        if getattr(self._thread_local, "read_only", False):
            logger.warning("SQLite fallback is read-only; dropping write for key '%s'", key)
            return
        try:
            if val_type == "set":
                data = list(data)
            val_raw = json.dumps(data)

            def _op() -> None:
                with self._lock:
                    conn = self._get_sqlite_conn()
                    try:
                        conn.execute(
                            """
                            INSERT INTO fallback_store (key, type, value)
                            VALUES (?, ?, ?)
                            ON CONFLICT(key) DO UPDATE SET
                                type=excluded.type,
                                value=excluded.value
                            """,
                            (key, val_type, val_raw),
                        )
                        conn.commit()
                    except Exception:
                        conn.rollback()
                        raise

            self._with_retry(_op, write=True)
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("SQLite fallback set error for key '%s': %s", key, exc)

    def db_del(self, key: str) -> int:
        """Delete key from SQLite."""
        if getattr(self._thread_local, "read_only", False):
            logger.warning("SQLite fallback is read-only; delete skipped for key '%s'", key)
            return 0
        try:

            def _op() -> int:
                with self._lock:
                    conn = self._get_sqlite_conn()
                    try:
                        cursor = conn.execute("DELETE FROM fallback_store WHERE key = ?", (key,))
                        deleted = cursor.rowcount
                        conn.commit()
                        return int(deleted)
                    except Exception:
                        conn.rollback()
                        raise

            deleted = self._with_retry(_op, write=True)
            return int(deleted)
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("SQLite fallback del error for key '%s': %s", key, exc)
            return 0

    def db_scan(self) -> list[str]:
        """Get all keys in fallback store."""
        try:

            def _op() -> Any:
                conn = self._get_sqlite_conn()
                return conn.execute("SELECT key FROM fallback_store").fetchall()

            rows = self._with_retry(_op)
            return [row["key"] for row in rows]
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("SQLite fallback scan error: %s", exc)
            return []

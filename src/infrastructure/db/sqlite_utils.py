"""Shared SQLite retry and safe-close helpers for the pipeline.

This module is the single source of truth for the SQLite connection
defaults used across the project:

* :data:`SQLITE_BUSY_TIMEOUT_MS` — passed as ``PRAGMA busy_timeout``
* :data:`SQLITE_CONNECT_TIMEOUT_SECONDS` — passed as ``sqlite3.connect(timeout=...)``
* :data:`SQLITE_LOCK_RETRY_ATTEMPTS` — how many times to retry a locked-DB op
* :data:`SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS` — base backoff for locked-DB op

Historically every module that opened a SQLite connection redefined
its own copy of these constants, with values drifting apart.  Use this
module's :func:`retrying_connect` (or the constants directly) instead.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Any, TypeVar

T = TypeVar("T")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


SQLITE_BUSY_TIMEOUT_MS: int = _env_int("SQLITE_BUSY_TIMEOUT_MS", 5000)
SQLITE_CONNECT_TIMEOUT_SECONDS: float = _env_float("SQLITE_CONNECT_TIMEOUT_SECONDS", 5.0)
SQLITE_LOCK_RETRY_ATTEMPTS: int = _env_int("SQLITE_LOCK_RETRY_ATTEMPTS", 4)
SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS: float = _env_float(
    "SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS", 0.05
)

# Back-compat aliases for the old underscore-prefixed names.
_DEFAULT_BUSY_TIMEOUT_MS = SQLITE_BUSY_TIMEOUT_MS
_DEFAULT_CONNECT_TIMEOUT_SECONDS = SQLITE_CONNECT_TIMEOUT_SECONDS
_DEFAULT_MAX_RETRIES = SQLITE_LOCK_RETRY_ATTEMPTS


@contextmanager
def retrying_connect(
    db_path: str | Any,
    *,
    busy_timeout_ms: int = SQLITE_BUSY_TIMEOUT_MS,
    max_retries: int = SQLITE_LOCK_RETRY_ATTEMPTS,
    connect_timeout_seconds: float = SQLITE_CONNECT_TIMEOUT_SECONDS,
    wal: bool = True,
    foreign_keys: bool = True,
) -> Generator[sqlite3.Connection, None, None]:
    """Open a SQLite connection with busy-timeout retry semantics.

    Yields a configured :class:`sqlite3.Connection` and rolls back any
    uncommitted transaction on exception.  Re-raises the last
    :class:`sqlite3.OperationalError` after exhausting retries.
    """
    last_exc: sqlite3.OperationalError | None = None
    for attempt in range(max(1, max_retries)):
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(
                str(db_path),
                timeout=connect_timeout_seconds,
                check_same_thread=False,
            )
            conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            conn.execute("PRAGMA synchronous=NORMAL")
            if wal:
                conn.execute("PRAGMA journal_mode=WAL")
            if foreign_keys:
                conn.execute("PRAGMA foreign_keys=ON")
            with _connection_scope(conn) as managed:
                yield managed
            return
        except sqlite3.OperationalError as exc:
            last_exc = exc
            if conn is not None:
                safe_close(conn)
            if attempt == max_retries - 1:
                raise
            time.sleep(SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS * (2**attempt))
    if last_exc is not None:
        raise last_exc


@contextmanager
def _connection_scope(conn: sqlite3.Connection) -> Generator[sqlite3.Connection, None, None]:
    """Wrap a SQLite connection in a try/except that rolls back on exception."""
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except sqlite3.ProgrammingError:
            pass
        raise


def safe_close(conn: sqlite3.Connection | None) -> None:
    """Close a SQLite connection, swallowing ``ProgrammingError`` on double-close."""
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.ProgrammingError:
        pass


def configure_connection(
    conn: sqlite3.Connection,
    *,
    busy_timeout_ms: int = SQLITE_BUSY_TIMEOUT_MS,
    wal: bool = True,
    foreign_keys: bool = True,
    synchronous: str = "NORMAL",
) -> None:
    """Apply the project's standard PRAGMA block to an open connection.

    Useful when a caller needs to control the connection lifecycle
    themselves (e.g. to keep it open across multiple operations inside
    a thread lock) and only wants the configuration applied.
    """
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    conn.execute("PRAGMA foreign_keys=ON")
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    if synchronous:
        conn.execute(f"PRAGMA synchronous={synchronous}")


def is_locked_error(exc: BaseException) -> bool:
    """Return True if ``exc`` looks like a SQLite database-locked error."""
    message = str(exc).lower()
    return "database is locked" in message or "database table is locked" in message


class _RetryDB:
    """Thread-safe locked-DB retry helper for callers that manage their own
    :class:`sqlite3.Connection` lifecycle.

    The default constants come from this module; tests may override them
    per-instance.
    """

    def __init__(
        self,
        *,
        max_attempts: int = SQLITE_LOCK_RETRY_ATTEMPTS,
        base_delay_seconds: float = SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS,
        is_locked: Callable[[BaseException], bool] = is_locked_error,
    ) -> None:
        self._max_attempts = max_attempts
        self._base_delay = base_delay_seconds
        self._is_locked = is_locked
        self._lock = threading.RLock()

    def run(self, operation: Callable[[], T]) -> T:
        """Run ``operation`` and retry on locked-DB errors with exponential backoff."""
        last_exc: sqlite3.OperationalError | None = None
        with self._lock:
            for attempt in range(self._max_attempts):
                try:
                    return operation()
                except sqlite3.OperationalError as exc:
                    last_exc = exc
                    if not self._is_locked(exc) or attempt == self._max_attempts - 1:
                        raise
                time.sleep(self._base_delay * (2**attempt))
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("retry_db: exhausted retries with no captured error")


__all__ = [
    "SQLITE_BUSY_TIMEOUT_MS",
    "SQLITE_CONNECT_TIMEOUT_SECONDS",
    "SQLITE_LOCK_RETRY_ATTEMPTS",
    "SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS",
    "retrying_connect",
    "safe_close",
    "configure_connection",
    "is_locked_error",
    "_RetryDB",
]

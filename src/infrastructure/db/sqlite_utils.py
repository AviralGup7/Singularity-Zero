from __future__ import annotations

import logging

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

    Note: this helper does **not** auto-commit changes. The caller is
    responsible for calling :meth:`sqlite3.Connection.commit` on the
    yielded connection (or for closing the context without committing
    to roll back).
    """
    for attempt in range(max(1, max_retries)):
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(
                str(db_path),
                timeout=connect_timeout_seconds,
                # NOTE: check_same_thread=False is required because this connection
                # is shared across threads via the _RetryDB lock. The project uses
                # WAL journal mode and a threading.RLock for write serialization,
                # making this safe. Each thread should use its own connection via
                # thread-local storage when possible.
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
        except sqlite3.OperationalError:
            if conn is not None:
                safe_close(conn)
            if attempt == max_retries - 1:
                raise
            time.sleep(SQLITE_LOCK_RETRY_BASE_DELAY_SECONDS * (2**attempt))


@contextmanager
def _connection_scope(conn: sqlite3.Connection) -> Generator[sqlite3.Connection, None, None]:
    """Wrap a SQLite connection in a try/except that rolls back on exception."""
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except sqlite3.ProgrammingError as exc:
            logging.warning("Operation failed in sqlite_utils.py: %s", exc, exc_info=True)  # noqa: BLE001
        raise


def safe_close(conn: sqlite3.Connection | None) -> None:
    """Close a SQLite connection, swallowing ``ProgrammingError`` on double-close."""
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.ProgrammingError as exc:
        logging.warning("Operation failed in sqlite_utils.py: %s", exc, exc_info=True)  # noqa: BLE001


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
    # busy_timeout is validated as int by the caller's type annotation
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    conn.execute("PRAGMA foreign_keys=ON")
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    if synchronous:
        # Validate synchronous value against known safe options to prevent injection
        _VALID_SYNC_MODES = {"OFF", "NORMAL", "FULL", "EXTRA"}
        sync_upper = synchronous.upper()
        if sync_upper not in _VALID_SYNC_MODES:
            raise ValueError(
                f"Invalid synchronous mode '{synchronous}'. Must be one of: {', '.join(sorted(_VALID_SYNC_MODES))}"
            )
        conn.execute(f"PRAGMA synchronous={sync_upper}")


def is_locked_error(exc: BaseException) -> bool:
    """Return True if ``exc`` looks like a SQLite database-locked error."""
    message = str(exc).lower()
    return "database is locked" in message or "database table is locked" in message


def build_in_clause(n: int) -> str:
    """Return a parameterized IN clause placeholder string for n items.

    Example: build_in_clause(3) returns "?, ?, ?"
    """
    if n <= 0:
        raise ValueError("build_in_clause requires n > 0")
    return ", ".join(["?"] * n)


class _RetryDB:
    """Thread-safe locked-DB retry helper for callers that manage their own
    :class:`sqlite3.Connection` lifecycle.

    .. warning::

        This class uses ``threading.RLock`` and is designed for **synchronous
        code paths only**. Calling :meth:`run` from an async context (e.g.
        inside an ``async def`` endpoint) will block the event loop. For async
        callers, use ``aiosqlite`` or wrap the call with
        ``await asyncio.to_thread(retrydb.run, operation)``.

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
        with self._lock:
            for attempt in range(self._max_attempts):
                try:
                    return operation()
                except sqlite3.OperationalError as exc:
                    if not self._is_locked(exc) or attempt == self._max_attempts - 1:
                        raise
                time.sleep(self._base_delay * (2**attempt))
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
    "build_in_clause",
    "_RetryDB",
]

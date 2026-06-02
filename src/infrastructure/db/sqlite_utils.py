"""Shared SQLite retry and safe-close helpers for the pipeline."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

_DEFAULT_BUSY_TIMEOUT_MS = 5000
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0


@contextmanager
def retrying_connect(
    db_path: str | Any,
    *,
    busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    connect_timeout_seconds: float = _DEFAULT_CONNECT_TIMEOUT_SECONDS,
    wal: bool = True,
    foreign_keys: bool = True,
) -> Generator[sqlite3.Connection, None, None]:
    """Open a SQLite connection with busy-timeout retry semantics."""

    last_exc: sqlite3.OperationalError | None = None
    for attempt in range(max(1, max_retries)):
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
            yield conn
            return
        except sqlite3.OperationalError as exc:
            last_exc = exc
            if attempt == max_retries - 1:
                raise
            time.sleep(0.05 * (2**attempt))
    if last_exc is not None:
        raise last_exc
    return None


def safe_close(conn: sqlite3.Connection | None) -> None:
    """Close a SQLite connection, swallowing ``ProgrammingError`` on double-close."""
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.ProgrammingError:
        pass

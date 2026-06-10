import logging
"""Base repository with connection management helpers."""

import json
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)


class BaseRepo:
    """Base class providing thread-local connection management."""

    _lock = threading.Lock()

    def __init__(self, db_path: Path, local: threading.local):
        self.db_path = db_path
        self._local = local

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
            except Exception:
                logger.debug("PRAGMA setup failed", exc_info=True)
                try:
                    conn.close()
                except sqlite3.ProgrammingError as exc:
                    logging.warning("Operation failed in base.py: %s", exc, exc_info=True)  # noqa: BLE001
                raise
            self._local.conn = conn
        return cast(sqlite3.Connection, self._local.conn)

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor]:
        """Context manager for a cursor with automatic commit/rollback."""
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            conn.execute("BEGIN")
            yield cur
            conn.execute("COMMIT")
        except Exception:
            logger.debug("Cursor operation failed, rolling back", exc_info=True)
            conn.execute("ROLLBACK")
            raise

    def _ensure_connection(self) -> None:
        """Ensure a connection has been established."""
        self._get_conn()

    @staticmethod
    def _bool_to_int(value: bool) -> int:
        """Convert a boolean to integer for SQLite storage."""
        return 1 if value else 0

    @staticmethod
    def _serialize_value(value: Any) -> str:
        """Serialize a value (dict/list) to JSON string for storage."""
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

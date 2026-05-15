"""Base repository with connection management helpers."""

import json
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast


class BaseRepo:
    """Base class providing thread-local connection management."""

    def __init__(self, db_path: Path, local: threading.local):
        self.db_path = db_path
        self._local = local

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return cast(sqlite3.Connection, self._local.conn)

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor]:
        """Context manager for a cursor with automatic commit/rollback."""
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
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

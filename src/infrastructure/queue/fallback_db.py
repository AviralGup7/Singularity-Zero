"""SQLite-backed fallback store data access layer for RedisClient.

Encapsulates data storage, retrieval, deletion, and schema management
used when the main Redis instance is unavailable.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class FallbackDB:
    """Manages SQLite access for the in-memory/disk fallback storage."""

    def __init__(self, db_path: str) -> None:
        """Initialize fallback database.

        Args:
            db_path: Absolute or relative path to the SQLite DB file.
        """
        self.db_path = db_path
        self._init_sqlite()

    def _init_sqlite(self) -> None:
        """Initialize the SQLite fallback database schema."""
        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS fallback_store (
                    key TEXT PRIMARY KEY,
                    type TEXT,
                    value TEXT
                )
                """
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Failed to initialize SQLite fallback database: %s", exc)

    def _get_sqlite_conn(self) -> Any:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        return conn

    def db_get(self, key: str) -> tuple[str | None, Any]:
        """Get key type and raw Python data from SQLite."""
        try:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT type, value FROM fallback_store WHERE key = ?", (key,))
            row = cursor.fetchone()
            conn.close()
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
        try:
            if val_type == "set":
                data = list(data)
            val_raw = json.dumps(data)
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute(
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
            conn.close()
        except Exception as exc:
            logger.error("SQLite fallback set error for key '%s': %s", key, exc)

    def db_del(self, key: str) -> int:
        """Delete key from SQLite."""
        try:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM fallback_store WHERE key = ?", (key,))
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            return int(deleted)
        except Exception as exc:
            logger.error("SQLite fallback del error for key '%s': %s", key, exc)
            return 0

    def db_scan(self) -> list[str]:
        """Get all keys in fallback store."""
        try:
            conn = self._get_sqlite_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM fallback_store")
            rows = cursor.fetchall()
            conn.close()
            return [row["key"] for row in rows]
        except Exception as exc:
            logger.error("SQLite fallback scan error: %s", exc)
            return []

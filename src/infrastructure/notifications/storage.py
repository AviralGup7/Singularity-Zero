"""SQLite-backed notification persistence for the dashboard.

Stores notifications so the frontend can:
  - Fetch historical notifications via REST
  - Mark individual / all notifications as read
  - Track read/unread state server-side
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from src.infrastructure.db.sqlite_utils import retrying_connect, safe_close

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    event TEXT NOT NULL,
    priority TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',
    source TEXT DEFAULT 'cyber-security-pipeline',
    correlation_id TEXT,
    entity_id TEXT,
    entity_type TEXT,
    href TEXT,
    read INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
"""

_CREATE_READ_INDEX = """
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
"""


class NotificationStorage:
    """Thread-safe SQLite store for notification persistence."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=5000")
                conn.executescript(_CREATE_TABLE)
                conn.execute(_CREATE_INDEX)
                conn.execute(_CREATE_READ_INDEX)
                conn.commit()
            except Exception:
                logger.exception("Failed to initialize notification storage")
            finally:
                safe_close(conn)

    def store(
        self,
        *,
        event: str,
        priority: str,
        title: str,
        message: str,
        metadata: dict[str, Any] | None = None,
        source: str = "cyber-security-pipeline",
        correlation_id: str | None = None,
        entity_id: str | None = None,
        entity_type: str | None = None,
        href: str | None = None,
    ) -> str:
        """Persist a notification and return its ID."""
        notif_id = f"notif-{uuid.uuid4().hex}"
        now = datetime.now(UTC).isoformat()

        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute(
                    """INSERT INTO notifications
                       (id, event, priority, title, message, metadata, source,
                        correlation_id, entity_id, entity_type, href, read, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
                    (
                        notif_id,
                        event,
                        priority,
                        title,
                        message,
                        json.dumps(metadata or {}),
                        source,
                        correlation_id,
                        entity_id,
                        entity_type,
                        href,
                        now,
                    ),
                )
                conn.commit()
            except Exception:
                logger.exception("Failed to store notification")
                notif_id = ""
            finally:
                safe_close(conn)

        return notif_id

    def list_notifications(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        unread_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Return notifications ordered by newest first."""
        query = "SELECT * FROM notifications"
        if unread_only:
            query += " WHERE read = 0"
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"

        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, (limit, offset))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except Exception:
                logger.exception("Failed to list notifications")
                return []
            finally:
                safe_close(conn)

    def count_unread(self) -> int:
        """Return the count of unread notifications."""
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                cursor = conn.execute("SELECT COUNT(*) FROM notifications WHERE read = 0")
                row = cursor.fetchone()
                return row[0] if row else 0
            except Exception:
                logger.exception("Failed to count unread notifications")
                return 0
            finally:
                safe_close(conn)

    def mark_read(self, notification_id: str) -> bool:
        """Mark a single notification as read. Returns True if a row was updated."""
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                cursor = conn.execute(
                    "UPDATE notifications SET read = 1 WHERE id = ? AND read = 0",
                    (notification_id,),
                )
                conn.commit()
                return cursor.rowcount > 0
            except Exception:
                logger.exception("Failed to mark notification as read")
                return False
            finally:
                safe_close(conn)

    def mark_all_read(self) -> int:
        """Mark all notifications as read. Returns count of updated rows."""
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                cursor = conn.execute("UPDATE notifications SET read = 1 WHERE read = 0")
                conn.commit()
                return cursor.rowcount
            except Exception:
                logger.exception("Failed to mark all notifications as read")
                return 0
            finally:
                safe_close(conn)

    def delete(self, notification_id: str) -> bool:
        """Delete a single notification."""
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                cursor = conn.execute("DELETE FROM notifications WHERE id = ?", (notification_id,))
                conn.commit()
                return cursor.rowcount > 0
            except Exception:
                logger.exception("Failed to delete notification")
                return False
            finally:
                safe_close(conn)

    def delete_all(self) -> int:
        """Delete all notifications. Returns count of deleted rows."""
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                cursor = conn.execute("DELETE FROM notifications")
                conn.commit()
                return cursor.rowcount
            except Exception:
                logger.exception("Failed to delete all notifications")
                return 0
            finally:
                safe_close(conn)

    def prune_old(self, max_age_hours: int = 48) -> int:
        """Delete notifications older than max_age_hours. Returns count deleted."""
        with self._lock:
            conn: sqlite3.Connection | None = None
            try:
                conn = sqlite3.connect(self._db_path, timeout=5.0)
                cursor = conn.execute(
                    """DELETE FROM notifications
                       WHERE created_at < datetime('now', ? || ' hours')""",
                    (-max_age_hours,),
                )
                conn.commit()
                return cursor.rowcount
            except Exception:
                logger.exception("Failed to prune old notifications")
                return 0
            finally:
                safe_close(conn)

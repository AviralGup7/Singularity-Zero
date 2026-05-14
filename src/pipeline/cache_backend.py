"""Lazy-loaded persistent cache backed by SQLite."""

import json
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

_DEFAULT_DB_PATH = os.environ.get(
    "RECON_CACHE_DB_PATH",
    str(Path(__file__).resolve().parent.parent / "output" / "cache" / "probe_cache.db"),
)


class _ThreadLocalConnections(threading.local):
    """Thread-local storage for SQLite connections."""

    def __init__(self) -> None:
        self.conn: sqlite3.Connection | None = None


class PersistentCache:
    """Thread-safe, file-backed cache using SQLite with TTL support."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._lock = threading.Lock()
        self._thread_local = _ThreadLocalConnections()
        self._init_db()

    def _ensure_thread_local(self) -> None:
        """Ensure _thread_local is initialized (handles __new__ bypass)."""
        if not hasattr(self, "_thread_local"):
            self._thread_local = _ThreadLocalConnections()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a cached per-thread SQLite connection, creating one if needed."""
        self._ensure_thread_local()
        if self._thread_local.conn is not None:
            return self._thread_local.conn
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        self._thread_local.conn = conn
        return conn

    def _close_conn(self) -> None:
        """Close the cached per-thread connection if it exists."""
        self._ensure_thread_local()
        if self._thread_local.conn is not None:
            try:
                self._thread_local.conn.close()
            except Exception as e:
                # Fix Audit #87: Log cache close failure
                logger.debug("Failed to close cache SQLite connection: %s", e)
            finally:
                self._thread_local.conn = None

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            try:
                conn = self._get_conn()
            except sqlite3.DatabaseError:
                db_path = Path(self._db_path)
                if db_path.exists():
                    try:
                        db_path.unlink()
                    except OSError as e:
                        logger.error("Failed to delete corrupted cache DB %s: %s", self._db_path, e)
                self._thread_local = _ThreadLocalConnections()
                conn = self._get_conn()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at ON cache_entries(expires_at)"
                )
                conn.commit()
            finally:
                self._close_conn()

    def get(self, key: str) -> Any | None:
        """Retrieve a value from the cache by key.

        Returns None if the key does not exist or the entry has expired.
        Expired entries are deleted on read.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "SELECT value, expires_at FROM cache_entries WHERE key = ?",
                    (key,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                value_str, expires_at = row
                if expires_at is not None and now >= expires_at:
                    conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    conn.commit()
                    return None
                return json.loads(value_str)
            finally:
                self._close_conn()

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                expires_at = now + ttl if ttl is not None else None
                value_str = json.dumps(value)
                conn.execute(
                    """
                    INSERT INTO cache_entries (key, value, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        created_at = excluded.created_at,
                        expires_at = excluded.expires_at
                    """,
                    (key, value_str, now, expires_at),
                )
                conn.commit()
            finally:
                self._close_conn()

    def delete(self, key: str) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                conn.commit()
            finally:
                self._close_conn()

    def clear(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM cache_entries")
                conn.commit()
            finally:
                self._close_conn()

    def cleanup_expired(self) -> int:
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "DELETE FROM cache_entries WHERE expires_at IS NOT NULL AND expires_at < ?",
                    (now,),
                )
                conn.commit()
                return cursor.rowcount
            finally:
                self._close_conn()

    def size(self) -> int:
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                row = cursor.fetchone()
                return row[0] if row else 0
            finally:
                self._close_conn()

    def validate_integrity(self) -> dict[str, Any]:
        """Check SQLite database health and return a status dict."""
        result: dict[str, Any] = {
            "healthy": True,
            "db_path": self._db_path,
            "entry_count": 0,
            "db_size_bytes": 0,
            "issues": [],
        }

        db_path = Path(self._db_path)
        if not db_path.exists():
            result["healthy"] = False
            result["issues"].append("Database file does not exist")
            return result

        result["db_size_bytes"] = db_path.stat().st_size

        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.execute("PRAGMA integrity_check")
            check_result = cursor.fetchone()
            if check_result and check_result[0] != "ok":
                result["healthy"] = False
                result["issues"].append(f"Integrity check failed: {check_result[0]}")
        except sqlite3.DatabaseError as exc:
            result["healthy"] = False
            result["issues"].append(f"Database error during integrity check: {exc}")
        finally:
            conn.close()

        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
            row = cursor.fetchone()
            result["entry_count"] = row[0] if row else 0
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            result["healthy"] = False
            result["issues"].append(f"Cannot query cache_entries: {exc}")
        finally:
            conn.close()

        if result["db_size_bytes"] > 100 * 1024 * 1024:
            result["issues"].append(
                f"Cache database is large ({result['db_size_bytes']} bytes). Consider cleanup."
            )

        if result["issues"]:
            logger.warning("Cache integrity issues: %s", result["issues"])

        return result

    def recover_from_corruption(self) -> bool:
        """Back up corrupted database and recreate it.

        Returns True if recovery succeeded, False otherwise.
        """
        if not hasattr(self, "_thread_local"):
            self._thread_local = _ThreadLocalConnections()
        db_path = Path(self._db_path)
        if not db_path.exists():
            self._init_db()
            return True

        integrity = self.validate_integrity()
        if integrity["healthy"]:
            return True

        backup_path = db_path.with_suffix(".db.corrupted.bak")
        try:
            if backup_path.exists():
                backup_path.unlink()
            shutil.copy2(str(db_path), str(backup_path))
            logger.info("Backed up corrupted cache to %s", backup_path)
        except OSError as exc:
            logger.error("Failed to back up corrupted cache: %s", exc)
            return False

        try:
            db_path.unlink()
        except OSError as exc:
            logger.error("Failed to remove corrupted cache: %s", exc)
            return False

        self._init_db()
        logger.info("Recreated cache database after corruption recovery")
        return True

    def get_disk_usage(self) -> dict[str, Any]:
        """Return cache size information."""
        db_path = Path(self._db_path)
        usage: dict[str, Any] = {
            "db_path": self._db_path,
            "db_size_bytes": 0,
            "entry_count": 0,
        }
        if db_path.exists():
            usage["db_size_bytes"] = db_path.stat().st_size
        usage["entry_count"] = self.size()
        return usage

    _DEFAULT_TTL = 86400

    def set_with_ttl(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Set a cache entry with an explicit TTL in seconds.

        Args:
            key: Cache key.
            value: Value to cache (must be JSON-serializable).
            ttl_seconds: Time-to-live in seconds. Defaults to 24 hours.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self._DEFAULT_TTL
        logger.debug("Setting cache key %s with TTL %ds", key, ttl)
        self.set(key, value, ttl=ttl)

    def get_cache_stats(self) -> dict[str, Any]:
        """Return cache statistics including size, entry count, and expired count.

        Returns:
            Dict with total_entries, active_entries, expired_entries,
            expired_count, db_size_bytes, and oldest_entry_age_seconds.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()

                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                total = cursor.fetchone()[0]

                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cache_entries WHERE expires_at IS NOT NULL AND expires_at < ?",
                    (now,),
                )
                expired = cursor.fetchone()[0]

                cursor = conn.execute("SELECT MIN(created_at) FROM cache_entries")
                row = cursor.fetchone()
                oldest_age = round(now - row[0], 1) if row and row[0] else 0

                db_size = 0
                db_path = Path(self._db_path)
                if db_path.exists():
                    db_size = db_path.stat().st_size

                return {
                    "total_entries": total,
                    "active_entries": total - expired,
                    "expired_entries": expired,
                    "db_size_bytes": db_size,
                    "oldest_entry_age_seconds": oldest_age,
                    "db_path": self._db_path,
                }
            finally:
                self._close_conn()

    def save_historical_scores(self, target_id: str, scores: list[dict[str, Any]]) -> None:
        """Persist historical endpoint scores for a target.

        Args:
            target_id: Target identifier.
            scores: List of historical score dicts.
        """
        key = f"historical_scores:{target_id}"
        logger.info("Saving historical scores for target %s (%d entries)", target_id, len(scores))
        self.set_with_ttl(key, scores, ttl_seconds=86400 * 30)

    def get_historical_scores(self, target_id: str) -> list[dict[str, Any]]:
        """Retrieve historical endpoint scores for a target.

        Args:
            target_id: Target identifier.

        Returns:
            List of historical score dicts, empty if none found.
        """
        key = f"historical_scores:{target_id}"
        result = self.get(key)
        return result if isinstance(result, list) else []

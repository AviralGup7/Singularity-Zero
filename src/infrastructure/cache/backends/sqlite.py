"""SQLite cache backend implementation.

Uses WAL mode and per-thread connections for concurrent read access.
Writing is serialised via a threading lock. Supports TTL, tags,
dependency tracking, and LRU metadata.
"""

from __future__ import annotations

import builtins
import json
import logging
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, cast

from .protocol import _ThreadLocalConnections

logger = logging.getLogger(__name__)



class SQLiteBackend:
    """SQLite-based cache backend with enhanced concurrency support.

    Uses WAL mode and per-thread connections for concurrent read access.
    Writing is serialized via a threading lock. Supports TTL, tags,
    dependency tracking, and LRU metadata.

    This is an enhanced version of the existing PersistentCache with:
    - Tag indexing for tag-based invalidation
    - Dependency tracking for cascade invalidation
    - Access tracking for LRU eviction
    - Namespace support for isolation
    - Better schema with additional columns

    Attributes:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str | None = None, max_entries: int = 10000) -> None:
        """Initialize the SQLite backend.

        Args:
            db_path: Path to the SQLite database. Defaults to cache_layer.db.
            max_entries: Maximum entries before LRU eviction triggers.
        """
        self._db_path = db_path or str(
            Path(__file__).resolve().parent.parent.parent.parent
            / "output"
            / "cache"
            / "cache_layer.db"
        )
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._thread_local = _ThreadLocalConnections()
        self._init_db()

    def _ensure_thread_local(self) -> None:
        """Ensure _thread_local is initialized (handles __new__ bypass)."""
        if not hasattr(self, "_thread_local"):
            self._thread_local = _ThreadLocalConnections()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a cached per-thread SQLite connection."""
        self._ensure_thread_local()
        if self._thread_local.conn is not None:
            return self._thread_local.conn
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        self._thread_local.conn = conn
        return conn

    def _close_conn(self) -> None:
        """Close the cached per-thread connection."""
        self._ensure_thread_local()
        if self._thread_local.conn is not None:
            try:
                self._thread_local.conn.close()
            except Exception:
                logger.debug("Failed to close SQLite cache connection")
            finally:
                self._thread_local.conn = None

    def _init_db(self) -> None:
        """Create the database schema if it does not exist."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            try:
                conn = self._get_conn()
            except sqlite3.DatabaseError:
                db_path = Path(self._db_path)
                if db_path.exists():
                    try:
                        db_path.unlink()
                    except OSError:
                        pass
                self._thread_local = _ThreadLocalConnections()
                conn = self._get_conn()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL,
                        last_accessed REAL NOT NULL,
                        access_count INTEGER DEFAULT 0,
                        tags TEXT DEFAULT '',
                        namespace TEXT DEFAULT 'default',
                        depends_on TEXT DEFAULT '',
                        metadata TEXT DEFAULT '{}'
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cache_expires_at ON cache_entries(expires_at)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cache_namespace ON cache_entries(namespace)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cache_last_accessed ON cache_entries(last_accessed)"
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_tags ON cache_entries(tags)")
                conn.commit()
            finally:
                self._close_conn()

    def get(self, key: str) -> Any | None:
        """Retrieve a value from the cache.

        Args:
            key: The cache key to look up.

        Returns:
            The cached value, or None if not found or expired.
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
                if expires_at is not None and now > expires_at:
                    conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    conn.commit()
                    return None
                conn.execute(
                    "UPDATE cache_entries SET last_accessed = ?, access_count = access_count + 1 WHERE key = ?",
                    (now, key),
                )
                conn.commit()
                return json.loads(value_str)
            finally:
                self._close_conn()

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value in the cache.

        Args:
            key: The cache key.
            value: The value to cache.
            ttl: Optional time-to-live in seconds.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                expires_at = now + ttl if ttl is not None else None
                value_str = json.dumps(value, default=str)
                conn.execute(
                    """
                    INSERT INTO cache_entries
                        (key, value, created_at, expires_at, last_accessed, access_count, tags, namespace, depends_on, metadata)
                    VALUES (?, ?, ?, ?, ?, 0, '', 'default', '', '{}')
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        created_at = excluded.created_at,
                        expires_at = excluded.expires_at,
                        last_accessed = excluded.last_accessed
                    """,
                    (key, value_str, now, expires_at, now),
                )
                conn.commit()
            finally:
                self._close_conn()

    def set_with_metadata(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
        tags: builtins.set[str] | None = None,
        namespace: str = "default",
        depends_on: builtins.set[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a value with extended metadata.

        Args:
            key: The cache key.
            value: The value to cache.
            ttl: Optional time-to-live in seconds.
            tags: Set of tags for tag-based invalidation.
            namespace: Namespace for isolation.
            depends_on: Set of keys this entry depends on.
            metadata: Additional metadata dictionary.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                expires_at = now + ttl if ttl is not None else None
                value_str = json.dumps(value, default=str)
                tags_str = ",".join(sorted(tags)) if tags else ""
                deps_str = ",".join(sorted(depends_on)) if depends_on else ""
                meta_str = json.dumps(metadata or {}, default=str)
                conn.execute(
                    """
                    INSERT INTO cache_entries
                        (key, value, created_at, expires_at, last_accessed, access_count, tags, namespace, depends_on, metadata)
                    VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        created_at = excluded.created_at,
                        expires_at = excluded.expires_at,
                        last_accessed = excluded.last_accessed,
                        tags = excluded.tags,
                        namespace = excluded.namespace,
                        depends_on = excluded.depends_on,
                        metadata = excluded.metadata
                    """,
                    (key, value_str, now, expires_at, now, tags_str, namespace, deps_str, meta_str),
                )
                conn.commit()
            finally:
                self._close_conn()

    def delete(self, key: str) -> bool:
        """Remove a specific entry from the cache.

        Args:
            key: The cache key to delete.

        Returns:
            True if the key existed and was deleted.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                self._close_conn()

    def delete_many(self, keys: list[str] | builtins.set[str]) -> int:
        """Remove multiple entries from the cache in one transaction.

        Args:
            keys: Collection of cache keys to delete.

        Returns:
            Number of entries deleted.
        """
        key_list = list(keys)
        if not key_list:
            return 0

        deleted = 0
        with self._lock:
            conn = self._get_conn()
            try:
                chunk_size = 900
                for i in range(0, len(key_list), chunk_size):
                    chunk = key_list[i : i + chunk_size]
                    placeholders = ",".join("?" * len(chunk))
                    query = f"DELETE FROM cache_entries WHERE key IN ({placeholders})"  # nosec: S608
                    cursor = conn.execute(query, chunk)
                    deleted += max(cursor.rowcount, 0)

                conn.commit()
                return deleted
            finally:
                self._close_conn()

    def exists(self, key: str) -> bool:
        """Check if a key exists and is not expired.

        Args:
            key: The cache key to check.

        Returns:
            True if the key exists and is not expired.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "SELECT expires_at FROM cache_entries WHERE key = ?",
                    (key,),
                )
                row = cursor.fetchone()
                if row is None:
                    return False
                expires_at = row[0]
                if expires_at is not None and now > expires_at:
                    return False
                return True
            finally:
                self._close_conn()

    def clear(self) -> int:
        """Remove all entries from the cache.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                count = cursor.fetchone()[0]
                conn.execute("DELETE FROM cache_entries")
                conn.commit()
                return count
            finally:
                self._close_conn()

    def size(self) -> int:
        """Return the number of non-expired entries.

        Returns:
            Count of active entries.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cache_entries WHERE expires_at IS NULL OR expires_at > ?",
                    (now,),
                )
                return int(cursor.fetchone()[0])
            finally:
                self._close_conn()

    def cleanup_expired(self) -> int:
        """Remove all expired entries.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "DELETE FROM cache_entries WHERE expires_at IS NOT NULL AND expires_at < ?",
                    (now,),
                )
                conn.commit()
                return cast(int, cursor.rowcount)
            finally:
                self._close_conn()

    def evict_lru(self, count: int) -> int:
        """Evict the least recently used entries.

        Args:
            count: Number of entries to evict.

        Returns:
            Number of entries actually evicted.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT key FROM cache_entries ORDER BY last_accessed ASC LIMIT ?",
                    (count,),
                )
                keys = [row[0] for row in cursor.fetchall()]
                if keys:
                    placeholders = ",".join("?" * len(keys))
                    query = f"DELETE FROM cache_entries WHERE key IN ({placeholders})"  # nosec: S608
                    conn.execute(query, keys)
                    conn.commit()
                return len(keys)
            finally:
                self._close_conn()

    def get_by_namespace(self, namespace: str) -> list[dict[str, Any]]:
        """Retrieve all entries in a namespace.

        Args:
            namespace: The namespace to query.

        Returns:
            List of dicts with key, value, and metadata.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "SELECT key, value, tags, namespace, depends_on, metadata FROM cache_entries WHERE namespace = ? AND (expires_at IS NULL OR expires_at > ?)",
                    (namespace, now),
                )
                results = []
                for row in cursor.fetchall():
                    results.append(
                        {
                            "key": row[0],
                            "value": json.loads(row[1]),
                            "tags": set(row[2].split(",")) if row[2] else set(),
                            "namespace": row[3],
                            "depends_on": set(row[4].split(",")) if row[4] else set(),
                            "metadata": json.loads(row[5]) if row[5] else {},
                        }
                    )
                return results
            finally:
                self._close_conn()

    def get_keys_by_namespace(self, namespace: str) -> list[str]:
        """Return all active keys in a namespace."""
        with self._lock:
            conn = self._get_conn()
            try:
                now = time.time()
                cursor = conn.execute(
                    "SELECT key FROM cache_entries WHERE namespace = ? AND (expires_at IS NULL OR expires_at > ?)",
                    (namespace, now),
                )
                return [row[0] for row in cursor.fetchall()]
            finally:
                self._close_conn()

    def get_by_tag(self, tag: str) -> list[str]:
        """Find all keys that have a specific tag.

        Args:
            tag: The tag to search for.

        Returns:
            List of matching cache keys.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    """
                    SELECT key
                    FROM cache_entries
                    WHERE tags = ?
                        OR tags LIKE ?
                        OR tags LIKE ?
                        OR tags LIKE ?
                    """,
                    (tag, f"{tag},%", f"%,{tag},%", f"%,{tag}"),
                )
                return [row[0] for row in cursor.fetchall()]
            finally:
                self._close_conn()

    def get_keys_by_tag(self, tag: str) -> list[str]:
        """Compatibility alias for tag lookup."""
        return self.get_by_tag(tag)

    def get_dependents(self, key: str) -> list[str]:
        """Find all entries that depend on a given key.

        Args:
            key: The key to find dependents for.

        Returns:
            List of keys that depend on the given key.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                pattern = f"%{key}%"
                cursor = conn.execute(
                    "SELECT key FROM cache_entries WHERE depends_on LIKE ?",
                    (pattern,),
                )
                return [row[0] for row in cursor.fetchall()]
            finally:
                self._close_conn()

    def get_stats(self) -> dict[str, Any]:
        """Return backend statistics.

        Returns:
            Dictionary with entry counts, database size, and health info.
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

                cursor = conn.execute("SELECT COUNT(DISTINCT namespace) FROM cache_entries")
                ns_count = cursor.fetchone()[0]

                db_size = 0
                db_path = Path(self._db_path)
                if db_path.exists():
                    db_size = db_path.stat().st_size

                return {
                    "backend": "sqlite",
                    "db_path": self._db_path,
                    "total_entries": total,
                    "active_entries": total - expired,
                    "expired_entries": expired,
                    "namespace_count": ns_count,
                    "db_size_bytes": db_size,
                    "healthy": True,
                }
            except Exception as exc:
                return {
                    "backend": "sqlite",
                    "db_path": self._db_path,
                    "healthy": False,
                    "error": str(exc),
                }
            finally:
                self._close_conn()

    def close(self) -> None:
        """Close the thread-local database connection."""
        self._close_conn()

    def recover_from_corruption(self) -> bool:
        """Back up corrupted database and recreate it.

        Returns:
            True if recovery succeeded.
        """
        db_path = Path(self._db_path)
        if not db_path.exists():
            self._init_db()
            return True

        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.execute("PRAGMA integrity_check")
            check_result = cursor.fetchone()
            conn.close()
            if check_result and check_result[0] == "ok":
                return True
        except sqlite3.DatabaseError:
            pass

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

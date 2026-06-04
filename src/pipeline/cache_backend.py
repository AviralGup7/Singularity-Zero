"""Lazy-loaded persistent cache backed by SQLite."""

import json
import os
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.cache.models import CacheMetrics
from src.infrastructure.cache.telemetry import build_cache_efficiency_snapshot
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
from src.infrastructure.db.sqlite_utils import (
    safe_close,
)

logger = get_pipeline_logger(__name__)

_DEFAULT_DB_PATH = os.environ.get(
    "RECON_CACHE_DB_PATH",
    str(Path(__file__).resolve().parent.parent / "output" / "cache" / "probe_cache.db"),
)


class _ThreadLocalConnections(threading.local):
    """Thread-local storage for SQLite connections."""

    def __init__(self) -> None:
        super().__init__()
        self.conn: sqlite3.Connection | None = None


class PersistentCache:
    """Thread-safe, file-backed cache using SQLite with TTL support."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._lock = threading.RLock()
        self._thread_local = _ThreadLocalConnections()
        self._all_conns: set[sqlite3.Connection] = set()
        self._metrics = CacheMetrics()
        self._init_db()

    def __del__(self) -> None:
        try:
            self.close_all()
        except Exception:  # noqa: S110
            pass

    def _ensure_thread_local(self) -> None:
        """Ensure all attributes are initialized (handles __new__ bypass)."""
        if not hasattr(self, "_db_path"):
            self._db_path = _DEFAULT_DB_PATH
        if not hasattr(self, "_lock"):
            self._lock = threading.RLock()
        if not hasattr(self, "_thread_local"):
            self._thread_local = _ThreadLocalConnections()
        if not hasattr(self, "_all_conns"):
            self._all_conns = set()
        if not hasattr(self, "_metrics"):
            self._metrics = CacheMetrics()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a cached per-thread SQLite connection, creating one if needed."""
        self._ensure_thread_local()
        if self._thread_local.conn is not None:
            return self._thread_local.conn
        conn = sqlite3.connect(
            self._db_path,
            timeout=_CONNECT_TIMEOUT_SECONDS,
            check_same_thread=False,
        )
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
        except Exception:
            try:
                conn.close()
            except sqlite3.ProgrammingError:
                pass
            raise
        self._thread_local.conn = conn
        with self._lock:
            if not hasattr(self, "_all_conns"):
                self._all_conns = set()
            self._all_conns.add(conn)
        return conn

    @staticmethod
    def _is_locked_error(exc: BaseException) -> bool:
        message = str(exc).lower()
        return "database is locked" in message or "database table is locked" in message

    @staticmethod
    def _is_transient_db_error(exc: BaseException) -> bool:
        """Return True if ``exc`` is a transient SQLite error that should
        not cause the database file to be deleted (e.g. disk full, locked).
        """
        message = str(exc).lower()
        transient_markers = (
            "disk full",
            "no space left",
            "database is locked",
            "database table is locked",
            "attempt to write a readonly database",
            "i/o error",
        )
        return any(marker in message for marker in transient_markers)

    def _with_retry(self, operation: Callable[[sqlite3.Connection], Any]) -> Any:
        last_exc: sqlite3.OperationalError | None = None
        for attempt in range(_LOCK_RETRY_ATTEMPTS):
            conn = self._get_conn()
            try:
                return operation(conn)
            except sqlite3.OperationalError as exc:
                last_exc = exc
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                self._close_conn()
                if not self._is_locked_error(exc) or attempt == _LOCK_RETRY_ATTEMPTS - 1:
                    self._metrics.record_error()
                    raise
                time.sleep(_LOCK_RETRY_BASE_DELAY_SECONDS * (2**attempt))
            except Exception:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                self._close_conn()
                self._metrics.record_error()
                raise
        if last_exc is not None:
            raise last_exc
        return None

    def _close_conn(self) -> None:
        """Close the cached per-thread connection if it exists."""
        self._ensure_thread_local()
        if self._thread_local.conn is not None:
            try:
                conn = self._thread_local.conn
                conn.close()
                with self._lock:
                    if hasattr(self, "_all_conns") and conn in self._all_conns:
                        self._all_conns.remove(conn)
            except Exception as e:
                # Fix Audit #87: Log cache close failure
                logger.debug("Failed to close cache SQLite connection: %s", e)
            finally:
                self._thread_local.conn = None

    def close_all(self) -> None:
        """Close all SQLite connections across all threads."""
        with self._lock:
            if hasattr(self, "_all_conns"):
                for conn in list(self._all_conns):
                    try:
                        safe_close(conn)
                    except Exception as e:
                        logger.debug("Failed to close SQLite connection: %s", e)
                self._all_conns.clear()
            self._ensure_thread_local()
            self._thread_local.conn = None

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            try:
                conn = self._get_conn()
            except sqlite3.DatabaseError as exc:
                # Distinguish transient (e.g. disk full, locked) from
                # integrity-corrupting (e.g. malformed header). Previously
                # *any* DatabaseError caused the entire cache file to be
                # deleted, which on transient disk-full events meant a
                # total cache wipe. Only delete when the file is genuinely
                # unreadable AND backup recovery is in place.
                db_path = Path(self._db_path)
                if self._is_transient_db_error(exc):
                    logger.warning(
                        "Transient SQLite error opening %s: %s; leaving file intact",
                        self._db_path,
                        exc,
                    )
                    raise
                if db_path.exists():
                    try:
                        # Back up before deletion so a forensic recovery is
                        # at least possible.
                        backup = db_path.with_suffix(db_path.suffix + ".corrupt.bak")
                        if backup.exists():
                            backup.unlink()
                        shutil.copy2(str(db_path), str(backup))
                    except OSError as e:
                        logger.error("Failed to back up corrupted cache DB %s: %s", self._db_path, e)
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
        start = time.monotonic()
        with self._lock:

            def _op(conn: sqlite3.Connection) -> Any | None:
                now = time.time()
                cursor = conn.execute(
                    "SELECT value, expires_at FROM cache_entries WHERE key = ?",
                    (key,),
                )
                row = cursor.fetchone()
                if row is None:
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_miss(elapsed)
                    return None
                value_str, expires_at = row
                if expires_at is not None and now >= expires_at:
                    conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    conn.commit()
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_miss(elapsed)
                    self._metrics.record_expiration()
                    return None
                try:
                    value = json.loads(value_str)
                except json.JSONDecodeError as exc:
                    logger.warning("Deleting corrupt cache entry for key %s: %s", key, exc)
                    conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    conn.commit()
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_miss(elapsed)
                    self._metrics.record_error()
                    return None
                elapsed = (time.monotonic() - start) * 1000
                self._metrics.record_hit(elapsed)
                return value

            return self._with_retry(_op)

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        start = time.monotonic()
        with self._lock:

            def _op(conn: sqlite3.Connection) -> None:
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
                elapsed = (time.monotonic() - start) * 1000
                self._metrics.record_set(elapsed)

            self._with_retry(_op)

    def delete(self, key: str) -> None:
        with self._lock:

            def _op(conn: sqlite3.Connection) -> None:
                conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                conn.commit()
                self._metrics.record_delete()

            self._with_retry(_op)

    def clear(self) -> None:
        with self._lock:

            def _op(conn: sqlite3.Connection) -> None:
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                row = cursor.fetchone()
                count = row[0] if row else 0
                conn.execute("DELETE FROM cache_entries")
                conn.commit()
                self._metrics.deletes += count

            self._with_retry(_op)

    def cleanup_expired(self) -> int:
        with self._lock:

            def _op(conn: sqlite3.Connection) -> int:
                now = time.time()
                cursor = conn.execute(
                    "DELETE FROM cache_entries WHERE expires_at IS NOT NULL AND expires_at <= ?",
                    (now,),
                )
                conn.commit()
                if cursor.rowcount > 0:
                    self._metrics.expirations += cursor.rowcount
                return int(cursor.rowcount)

            return int(self._with_retry(_op))

    def prune_oldest(self, count: int) -> int:
        """Remove the N oldest entries from the cache regardless of expiration."""
        if count <= 0:
            return 0
        with self._lock:

            def _op(conn: sqlite3.Connection) -> int:
                cursor = conn.execute(
                    "DELETE FROM cache_entries WHERE key IN (SELECT key FROM cache_entries ORDER BY created_at ASC LIMIT ?)",
                    (count,),
                )
                conn.commit()
                return int(cursor.rowcount)

            return int(self._with_retry(_op))

    def prune_prefix(self, prefix: str) -> int:
        """Remove every entry whose key starts with ``prefix``.

        Returns the number of rows deleted. Used by namespaced cache users
        (e.g. ``probe:``) to clear their slice without touching unrelated
        pipeline cache entries.
        """
        if not prefix:
            return 0
        with self._lock:

            def _op(conn: sqlite3.Connection) -> int:
                cursor = conn.execute(
                    "DELETE FROM cache_entries WHERE key LIKE ?",
                    (f"{prefix}%",),
                )
                conn.commit()
                return int(cursor.rowcount)

            return int(self._with_retry(_op))

    def keys_with_prefix(self, prefix: str) -> list[str]:
        """Return all cache keys that start with ``prefix``."""
        if not prefix:
            return []
        with self._lock:

            def _op(conn: sqlite3.Connection) -> list[str]:
                cursor = conn.execute(
                    "SELECT key FROM cache_entries WHERE key LIKE ?",
                    (f"{prefix}%",),
                )
                return [row[0] for row in cursor.fetchall()]

            return list(self._with_retry(_op))

    def size(self) -> int:
        with self._lock:

            def _op(conn: sqlite3.Connection) -> int:
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                row = cursor.fetchone()
                return int(row[0]) if row else 0

            return int(self._with_retry(_op))

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

        with self._lock:
            try:
                conn = self._get_conn()
                try:
                    cursor = conn.execute("PRAGMA integrity_check")
                    check_result = cursor.fetchone()
                    if check_result and check_result[0] != "ok":
                        result["healthy"] = False
                        result["issues"].append(f"Integrity check failed: {check_result[0]}")
                except sqlite3.DatabaseError as exc:
                    result["healthy"] = False
                    result["issues"].append(f"Database error during integrity check: {exc}")

                try:
                    cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                    row = cursor.fetchone()
                    result["entry_count"] = row[0] if row else 0
                except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
                    result["healthy"] = False
                    result["issues"].append(f"Cannot query cache_entries: {exc}")
            except sqlite3.DatabaseError as exc:
                result["healthy"] = False
                result["issues"].append(f"Failed to get thread-local connection: {exc}")

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
        self.close_all()
        try:
            if backup_path.exists():
                backup_path.unlink()
            shutil.copy2(str(db_path), str(backup_path))
            logger.info("Backed up corrupted cache to %s", backup_path)
        except OSError as exc:
            logger.error("Failed to back up corrupted cache: %s", exc)
            return False

        try:
            for path in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
                if path.exists():
                    path.unlink()
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
        try:
            usage["entry_count"] = self.size()
        except sqlite3.DatabaseError as exc:
            logger.warning("Failed to calculate cache disk usage entry count: %s", exc)
            usage["error"] = str(exc)
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

            def _op(conn: sqlite3.Connection) -> dict[str, Any]:
                now = time.time()

                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                total = cursor.fetchone()[0]

                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cache_entries WHERE expires_at IS NOT NULL AND expires_at <= ?",
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

            return dict(self._with_retry(_op))

    def get_metrics(self) -> CacheMetrics:
        """Return runtime cache metrics."""
        return self._metrics

    def get_metrics_snapshot(self) -> dict[str, Any]:
        """Return runtime cache metrics as a plain dict."""
        return self._metrics.snapshot()

    def get_efficiency_snapshot(self) -> dict[str, Any]:
        """Return cache efficiency telemetry for shared API consumers."""
        return build_cache_efficiency_snapshot(self, backend_type="sqlite")

    def reset_metrics(self) -> None:
        """Reset runtime cache metrics."""
        self._metrics.reset()

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

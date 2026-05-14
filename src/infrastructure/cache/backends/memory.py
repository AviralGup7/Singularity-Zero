"""In-memory cache backend implementation.

Simple dictionary-based cache with TTL support.
Not persistent - all data is lost when the process exits.
Thread-safe via threading.Lock.
"""

import builtins
import threading
import time
from typing import Any





class MemoryBackend:
    """In-memory cache backend for testing and L1 tier.

    Simple dictionary-based cache with TTL support.
    Not persistent - all data is lost when the process exits.

    Thread-safe via threading.Lock.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        """Initialize the memory backend.

        Args:
            max_entries: Maximum entries before eviction.
        """
        self._store: dict[str, dict[str, Any]] = {}
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        """Retrieve a value from memory."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at = entry.get("expires_at")
            if expires_at is not None and time.time() > expires_at:
                del self._store[key]
                return None
            entry["last_accessed"] = time.time()
            entry["access_count"] = entry.get("access_count", 0) + 1
            return entry.get("value")

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value in memory."""
        with self._lock:
            now = time.time()
            expires_at = now + ttl if ttl is not None else None
            self._store[key] = {
                "value": value,
                "created_at": now,
                "expires_at": expires_at,
                "last_accessed": now,
                "access_count": 0,
            }

    def delete(self, key: str) -> bool:
        """Remove a key from memory."""
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def delete_many(self, keys: list[str] | builtins.set[str]) -> int:
        """Remove multiple keys from memory in one lock acquisition."""
        with self._lock:
            removed = 0
            for key in keys:
                if key in self._store:
                    del self._store[key]
                    removed += 1
            return removed

    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return False
            expires_at = entry.get("expires_at")
            if expires_at is not None and time.time() > expires_at:
                return False
            return True

    def clear(self) -> int:
        """Remove all entries."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            return count

    def size(self) -> int:
        """Return the number of active entries."""
        with self._lock:
            now = time.time()
            return sum(
                1
                for entry in self._store.values()
                if entry.get("expires_at") is None or entry["expires_at"] > now
            )

    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        with self._lock:
            now = time.time()
            expired = [
                key
                for key, entry in self._store.items()
                if entry.get("expires_at") is not None and entry["expires_at"] < now
            ]
            for key in expired:
                del self._store[key]
            return len(expired)

    def evict_lru(self, count: int) -> int:
        """Evict the least recently used entries."""
        with self._lock:
            sorted_keys = sorted(
                self._store.keys(),
                key=lambda k: self._store[k].get("last_accessed", 0),
            )
            to_evict = sorted_keys[:count]
            for key in to_evict:
                del self._store[key]
            return len(to_evict)

    def get_all(self) -> dict[str, Any]:
        """Return all non-expired entries."""
        with self._lock:
            now = time.time()
            result = {}
            expired = []
            for key, entry in self._store.items():
                if entry.get("expires_at") is not None and entry["expires_at"] < now:
                    expired.append(key)
                else:
                    result[key] = entry.get("value")
            for key in expired:
                del self._store[key]
            return result

    def get_keys_by_namespace(self, namespace: str) -> list[str]:
        """Return all keys in a namespace."""
        prefix = f"{namespace}:"
        with self._lock:
            return [k for k in self._store if k.startswith(prefix)]

    def get_keys_by_tag(self, tag: str) -> list[str]:
        """Return all keys (memory backend has no tag index)."""
        return []

    def get_stats(self) -> dict[str, Any]:
        """Return memory backend statistics."""
        with self._lock:
            now = time.time()
            total = len(self._store)
            expired = sum(
                1
                for entry in self._store.values()
                if entry.get("expires_at") is not None and entry["expires_at"] < now
            )
            return {
                "backend": "memory",
                "total_entries": total,
                "active_entries": total - expired,
                "expired_entries": expired,
                "max_entries": self._max_entries,
                "healthy": True,
            }

    def close(self) -> None:
        """Clear all entries (memory backend has no persistence)."""
        with self._lock:
            self._store.clear()

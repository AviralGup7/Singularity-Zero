r"""File-based cache backend implementation.

Compatible with the existing pipeline_platform/cache.py format.
Each cache entry is stored as a separate JSON file with optional
gzip compression.
"""

import builtins
import gzip
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FileBackend:
    """File-based cache backend using JSON files.

    Compatible with the existing pipeline_platform/cache.py format.
    Each cache entry is stored as a separate JSON file with optional
    gzip compression.

    Attributes:
        cache_dir: Base directory for cache files.
        enable_compression: Whether to use gzip compression.
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        max_entries: int = 10000,
        enable_compression: bool = True,
    ) -> None:
        """Initialize the file backend.

        Args:
            cache_dir: Base directory for cache files.
            max_entries: Maximum number of files to maintain.
            enable_compression: Whether to gzip-compress files.
        """
        self._cache_dir = cache_dir or str(
            Path(__file__).resolve().parent.parent.parent.parent / "output" / "cache" / "files"
        )
        self._max_entries = max_entries
        self._enable_compression = enable_compression
        self._lock = threading.RLock()
        self._index: dict[str, dict[str, Any]] = {}
        self._load_index()

    def _load_index(self) -> None:
        """Load the cache index from disk."""
        index_path = Path(self._cache_dir) / ".cache_index.json"
        if index_path.exists():
            try:
                self._index = json.loads(index_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._index = {}

    def _save_index(self) -> None:
        """Persist the cache index to disk."""
        index_path = Path(self._cache_dir) / ".cache_index.json"
        Path(self._cache_dir).mkdir(parents=True, exist_ok=True)
        tmp_fd: int | None = None
        tmp_path: str | None = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(dir=self._cache_dir, suffix=".tmp")
            os.chmod(tmp_path, 0o600)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                tmp_fd = None
                json.dump(self._index, f, default=str)
            os.replace(tmp_path, str(index_path))
            tmp_path = None
        except OSError:
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            pass

    def _file_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        safe_prefix = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in key)[:80]
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return Path(self._cache_dir) / f"{safe_prefix}.{digest}.json"

    def _legacy_file_path(self, key: str) -> Path:
        """Return the pre-hash filename used by older cache versions."""
        safe_key = key.replace(":", "_").replace("/", "_").replace("\\", "_")
        return Path(self._cache_dir) / f"{safe_key}.json"

    def _file_path_compressed(self, key: str) -> Path:
        """Get the compressed file path for a cache key."""
        return self._file_path(key).with_suffix(".json.gz")

    def get(self, key: str) -> Any | None:
        """Retrieve a value from a JSON file."""
        with self._lock:
            entry = self._index.get(key)
            if entry is None:
                return self._load_from_file(key)
            expires_at = entry.get("expires_at")
            if expires_at is not None and time.time() > expires_at:
                self._delete_file(key)
                self._index.pop(key, None)
                return None
            return entry.get("value")

    def _load_from_file(self, key: str) -> Any | None:
        """Load a value directly from disk."""
        candidate_paths = [
            self._file_path_compressed(key),
            self._file_path(key),
            self._legacy_file_path(key).with_suffix(".json.gz"),
            self._legacy_file_path(key),
        ]

        entry = None
        for path in candidate_paths:
            if not path.exists():
                continue
            try:
                if path.suffix == ".gz":
                    data = gzip.decompress(path.read_bytes())
                    entry = json.loads(data.decode("utf-8"))
                else:
                    entry = json.loads(path.read_text(encoding="utf-8"))
                break
            except (EOFError, UnicodeDecodeError, json.JSONDecodeError, OSError):
                continue

        if entry is None:
            return None

        expires_at = entry.get("expires_at")
        if expires_at is not None and time.time() >= expires_at:
            self._delete_file(key)
            return None

        self._index[key] = entry
        return entry.get("value")

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value in a JSON file."""
        with self._lock:
            now = time.time()
            expires_at = now + ttl if ttl is not None else None
            entry = {
                "key": key,
                "value": value,
                "created_at": now,
                "expires_at": expires_at,
                "last_accessed": now,
            }
            self._index[key] = entry
            self._write_file(key, entry)
            self._save_index()
            if len(self._index) > self._max_entries:
                self.evict_lru(len(self._index) - self._max_entries)

    def _write_file(self, key: str, entry: dict[str, Any]) -> None:
        """Write an entry to a file."""
        Path(self._cache_dir).mkdir(parents=True, exist_ok=True)
        data = json.dumps(entry, default=str).encode("utf-8")

        if self._enable_compression:
            path = self._file_path_compressed(key)
            data = gzip.compress(data, compresslevel=6)
        else:
            path = self._file_path(key)

        tmp_path: str | None = None
        tmp_fd: int | None = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(dir=self._cache_dir, suffix=".tmp")
            os.chmod(tmp_path, 0o600)
            with os.fdopen(tmp_fd, "wb") as f:
                tmp_fd = None
                f.write(data)
            os.replace(tmp_path, str(path))
            tmp_path = None
        except OSError as exc:
            logger.warning("File cache write failed for key '%s': %s", key, exc)
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            try:
                from src.infrastructure.observability.metrics import get_metrics
                get_metrics().counter("file_cache_write_failures_total", "Total file cache write failures").inc()
            except Exception:
                pass

    def _delete_file(self, key: str) -> bool:
        """Delete cache files for a key."""
        deleted = False
        paths = [
            self._file_path(key),
            self._file_path_compressed(key),
            self._legacy_file_path(key),
            self._legacy_file_path(key).with_suffix(".json.gz"),
        ]
        for path in paths:
            try:
                if path.exists():
                    path.unlink()
                    deleted = True
            except OSError:
                pass
        return deleted

    def delete(self, key: str) -> bool:
        """Remove a cache entry."""
        with self._lock:
            existed = key in self._index
            file_deleted = self._delete_file(key)
            self._index.pop(key, None)
            if existed or file_deleted:
                self._save_index()
            return existed or file_deleted

    def delete_many(self, keys: list[str] | builtins.set[str]) -> int:
        """Remove multiple cache entries in a single index write."""
        with self._lock:
            removed = 0
            for key in keys:
                existed = key in self._index
                self._delete_file(key)
                if existed:
                    removed += 1
                self._index.pop(key, None)

            if removed:
                self._save_index()

            return removed

    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        with self._lock:
            entry = self._index.get(key)
            if entry is None:
                self._load_from_file(key)
                return key in self._index
            expires_at = entry.get("expires_at")
            if expires_at is not None and time.time() >= expires_at:
                self._delete_file(key)
                self._index.pop(key, None)
                self._save_index()
                return False
            return True

    def clear(self) -> int:
        """Remove all cache files."""
        with self._lock:
            count = len(self._index)
            for key in list(self._index):
                self._delete_file(key)
            self._index.clear()
            cache_path = Path(self._cache_dir)
            if cache_path.exists():
                for path in cache_path.iterdir():
                    if path.is_file() and path.name != ".cache_index.json":
                        try:
                            path.unlink()
                        except OSError:
                            pass
            self._save_index()
            return count

    def size(self) -> int:
        """Return the number of active entries."""
        with self._lock:
            now = time.time()
            return sum(
                1
                for entry in self._index.values()
                if entry.get("expires_at") is None or entry["expires_at"] > now
            )

    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        with self._lock:
            now = time.time()
            expired = [
                key
                for key, entry in self._index.items()
                if entry.get("expires_at") is not None and entry["expires_at"] <= now
            ]
            for key in expired:
                self._delete_file(key)
                del self._index[key]
            if expired:
                self._save_index()
            return len(expired)

    def evict_lru(self, count: int) -> int:
        """Evict the least recently used entries."""
        if count <= 0:
            return 0
        with self._lock:
            sorted_keys = sorted(
                self._index.keys(),
                key=lambda k: self._index[k].get("last_accessed", 0),
            )
            to_evict = sorted_keys[:count]
            for key in to_evict:
                self._delete_file(key)
                self._index.pop(key, None)
            if to_evict:
                self._save_index()
            return len(to_evict)

    def get_ttl_remaining(self, key: str) -> float | None:
        """Return remaining TTL for an active key, or None for no expiry/missing."""
        with self._lock:
            entry = self._index.get(key)
            if entry is None:
                self._load_from_file(key)
                entry = self._index.get(key)
            if entry is None:
                return None
            expires_at = entry.get("expires_at")
            if expires_at is None:
                return None
            remaining = expires_at - time.time()
            if remaining <= 0:
                self._delete_file(key)
                self._index.pop(key, None)
                self._save_index()
                return 0.0
            return remaining

    def get_stats(self) -> dict[str, Any]:
        """Return file backend statistics."""
        cache_path = Path(self._cache_dir)
        total_size = 0
        file_count = 0
        if cache_path.exists():
            for f in cache_path.iterdir():
                if f.is_file():
                    total_size += f.stat().st_size
                    file_count += 1

        return {
            "backend": "file",
            "cache_dir": self._cache_dir,
            "index_entries": len(self._index),
            "file_count": file_count,
            "total_size_bytes": total_size,
            "compression": self._enable_compression,
            "healthy": True,
        }

    def close(self) -> None:
        """Persist the index and release resources."""
        with self._lock:
            self._save_index()

    def get_keys_by_namespace(self, namespace: str) -> list[str]:
        """Return all keys in a namespace."""
        prefix = f"{namespace}:"
        with self._lock:
            now = time.time()
            expired = [
                key
                for key, entry in self._index.items()
                if entry.get("expires_at") is not None and entry["expires_at"] <= now
            ]
            for key in expired:
                self._delete_file(key)
                self._index.pop(key, None)
            if expired:
                self._save_index()
            return [k for k in self._index if k.startswith(prefix)]

    def get_keys_by_tag(self, tag: str) -> list[str]:
        """Return all keys (file backend has no tag index)."""
        return []

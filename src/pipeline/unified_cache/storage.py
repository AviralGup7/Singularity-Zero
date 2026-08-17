"""UnifiedCache — single facade over SQLite and on-disk blobs."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.cache_backend import PersistentCache
from src.pipeline.unified_cache.coalescing import CoalescingCacheWrapper
from src.pipeline.unified_cache.models import (
    _DATA_PREFIX,
    _ROUTING_PREFIX,
    PRIORITY_RANK,
    Backend,
    CachePriority,
    TTLMode,
)
from src.pipeline.unified_cache.policies import (
    CacheKeyNormalizer,
    _atomic_write_bytes,
    _hash_key,
    _parse_namespace,
    _resolve_routing,
)

logger = get_pipeline_logger(__name__)


class UnifiedCache:
    """Single facade over SQLite (``PersistentCache``) and on-disk blobs.

    All entries are addressed by a fully-qualified key of the form
    ``"<namespace>:<rest>"``. The facade consults ``NAMESPACE_ROUTING`` to
    decide which physical store receives the bytes and records the routing
    decision in a per-key index so reads, deletes, and prune operations
    affect every copy.

    Concurrency: the facade serializes routing-index updates with a thread
    lock. The underlying ``PersistentCache`` already provides per-thread
    SQLite connections with WAL.

    Singleton: use ``get_unified_cache()`` to obtain the process-wide instance.
    Direct ``UnifiedCache()`` calls are permitted but should be avoided outside
    of tests or explicitly isolated subsystems.
    """

    _instance: UnifiedCache | None = None
    _initializing: bool = False

    def __new__(
        cls,
        *,
        sqlite_backend: PersistentCache | None = None,
        file_root: Path | str | None = None,
        strict_namespaces: bool = False,
        max_coalesce_workers: int = 8,
    ) -> UnifiedCache:
        if cls._instance is not None and not cls._initializing:
            if sqlite_backend is None and file_root is None:
                return cls._instance
        instance = super().__new__(cls)
        return instance

    def __init__(
        self,
        *,
        sqlite_backend: PersistentCache | None = None,
        file_root: Path | str | None = None,
        strict_namespaces: bool = False,
        max_coalesce_workers: int = 8,
    ) -> None:
        if UnifiedCache._instance is not None and not self._initializing:
            if sqlite_backend is None and file_root is None:
                return
        UnifiedCache._initializing = True
        try:
            self._sqlite = sqlite_backend if sqlite_backend is not None else PersistentCache()
            if file_root is None:
                default_dir = (
                    Path(__file__).resolve().parent.parent.parent
                    / "output"
                    / "cache"
                    / "unified_blobs"
                )
                self._file_root = default_dir
            else:
                self._file_root = Path(file_root)
            self._file_root.mkdir(parents=True, exist_ok=True)
            self._strict = strict_namespaces
            self._lock = threading.RLock()
            capped_workers = min(max_coalesce_workers, 16)
            self._coalesce = CoalescingCacheWrapper(self, max_workers=capped_workers)
            self._refresh_executor = ThreadPoolExecutor(
                max_workers=max(1, capped_workers // 2), thread_name_prefix="cache-refresh"
            )
            UnifiedCache._instance = self
        finally:
            UnifiedCache._initializing = False
        self._register_with_lifecycle()

    def _shutdown_refresh_executor(self) -> None:
        """Gracefully shut down the refresh executor at process exit."""
        try:
            self._refresh_executor.shutdown(wait=True)
        except Exception:
            logger.debug("Non-critical cleanup error", exc_info=True)

    def _register_with_lifecycle(self) -> None:
        try:
            from src.core.lifecycle import get_lifecycle_manager

            get_lifecycle_manager().register_shutdown(
                "unified_cache_refresh",
                self._shutdown_refresh_executor,
                after=["cache_manager"],
            )
        except ImportError:
            pass

    @property
    def sqlite(self) -> PersistentCache:
        """Return the underlying SQLite backend."""
        return self._sqlite

    @property
    def file_root(self) -> Path:
        """Return the on-disk blob directory."""
        return self._file_root

    def _routing_key(self, key: str) -> str:
        return f"{_ROUTING_PREFIX}{key}"

    def _data_key(self, key: str) -> str:
        return f"{_DATA_PREFIX}{key}"

    def _file_key(self, key: str) -> str:
        return f"{_DATA_PREFIX}{key}_file"

    def _file_path_for(self, namespace: str, key: str) -> Path:
        return self._file_root / namespace / f"{_hash_key(key)}.bin"

    def _read_routing(self, key: str) -> dict[str, Any] | None:
        record = self._sqlite.get(self._routing_key(key))
        if isinstance(record, dict):
            return record
        return None

    def _write_routing(self, key: str, record: dict[str, Any], ttl: int | None) -> None:
        self._sqlite.set(self._routing_key(key), record, ttl=ttl)

    def _scrub_routing(self, key: str) -> None:
        """Remove routing index entry with forensic logging."""
        logger.info("unified_cache scrubbing routing for key=%s", key)
        self._sqlite.delete(self._routing_key(key))

    def set(
        self,
        key: str,
        value: Any,
        *,
        ttl: int | None = None,
        priority: CachePriority | None = None,
        ttl_mode: TTLMode | None = None,
        stale_threshold_hours: int | None = None,
    ) -> Backend:
        key = CacheKeyNormalizer.normalize(key)
        namespace = _parse_namespace(key)
        routing = _resolve_routing(namespace, self._strict)

        try:
            serialized = json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"value for {key!r} is not JSON-serialisable: {exc}") from exc
        payload = serialized.encode("utf-8")
        size = len(payload)

        backend = routing.default_backend
        if routing.split_threshold_bytes is not None and size >= routing.split_threshold_bytes:
            backend = Backend.FILE

        chosen_priority = priority.value if priority is not None else routing.default_priority.value
        effective_mode = (ttl_mode or TTLMode.HARD_TTL).value

        with self._lock:
            if backend == Backend.SQLITE:
                self._sqlite.set(self._data_key(key), value, ttl=ttl)
                record = {
                    "backend": backend.value,
                    "size_bytes": size,
                    "priority": chosen_priority,
                    "ttl_mode": effective_mode,
                    "stale_threshold_hours": stale_threshold_hours,
                    "created_at": time.time(),
                }
                self._write_routing(key, record, ttl=ttl)
            else:
                path = self._file_path_for(namespace, key)
                _atomic_write_bytes(path, payload)
                record = {
                    "backend": backend.value,
                    "path": str(path),
                    "size_bytes": size,
                    "priority": chosen_priority,
                    "ttl_mode": effective_mode,
                    "stale_threshold_hours": stale_threshold_hours,
                    "created_at": time.time(),
                }
                self._write_routing(key, record, ttl=ttl)
        return backend

    def get(self, key: str) -> Any | None:
        key = CacheKeyNormalizer.normalize(key)
        with self._lock:
            record = self._read_routing(key)
            if record is None:
                return None
            backend = record.get("backend")
            if backend == Backend.SQLITE.value:
                value = self._sqlite.get(self._data_key(key))
                if value is None:
                    self._scrub_routing(key)
                    logger.debug("unified_cache scrub orphan sqlite index for %s", key)
                return value
            if backend == Backend.FILE.value:
                path_str = record.get("path")
                if not isinstance(path_str, str):
                    self._scrub_routing(key)
                    return None
                path = Path(path_str)
                if not path.exists():
                    self._scrub_routing(key)
                    logger.debug("unified_cache scrub orphan file index for %s", key)
                    return None
                try:
                    raw = path.read_bytes()
                    return json.loads(raw.decode("utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    logger.warning(
                        "unified_cache corrupt blob for %s (%s): %s",
                        key,
                        exc.__class__.__name__,
                        exc,
                    )
                    self._delete_file(path)
                    self._scrub_routing(key)
                    return None
            self._scrub_routing(key)
            return None

    def delete(self, key: str) -> bool:
        key = CacheKeyNormalizer.normalize(key)
        with self._lock:
            record = self._read_routing(key)
            if record is None:
                return False
            self._scrub_routing(key)
            backend = record.get("backend")
            if backend == Backend.SQLITE.value:
                self._sqlite.delete(self._data_key(key))
                return True
            if backend == Backend.FILE.value:
                path_str = record.get("path")
                if isinstance(path_str, str):
                    self._delete_file(Path(path_str))
                return True
            return False

    def exists(self, key: str) -> bool:
        """Return whether ``key`` resolves to a live value."""
        return self.get(key) is not None

    def _delete_file(self, path: Path) -> None:
        """Move corrupted file to quarantine instead of deleting it."""
        try:
            if path.exists():
                quarantine_dir = self._file_root / "_quarantine"
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                quarantine_path = quarantine_dir / f"{path.stem}_{int(time.time())}{path.suffix}"
                try:
                    path.rename(quarantine_path)
                    logger.warning(
                        "unified_cache quarantined corrupt blob %s -> %s",
                        path,
                        quarantine_path,
                    )
                except OSError:
                    path.unlink()
                    logger.warning(
                        "unified_cache deleted corrupt blob %s (quarantine failed)", path
                    )
        except OSError as exc:
            logger.warning("unified_cache failed to delete blob %s: %s", path, exc)

    def keys_with_prefix(self, prefix: str) -> list[str]:
        """Return keys (without the internal routing prefix) starting with ``prefix``."""
        raw = self._sqlite.keys_with_prefix(f"{_ROUTING_PREFIX}{prefix}")
        return [key[len(_ROUTING_PREFIX) :] for key in raw]

    def prune_prefix(self, prefix: str) -> int:
        """Delete every entry whose key starts with ``prefix``. Returns count."""
        with self._lock:
            keys = self.keys_with_prefix(prefix)
            removed = 0
            for key in keys:
                if self.delete(key):
                    removed += 1
            return removed

    def cleanup_expired(self) -> int:
        """Drop expired SQLite entries and orphaned file blobs they pointed to."""
        before = set(self.keys_with_prefix(""))
        sqlite_dropped = self._sqlite.cleanup_expired()
        after = set(self.keys_with_prefix(""))
        evicted = before - after
        for key in evicted:
            namespace = _parse_namespace(key)
            candidate = self._file_path_for(namespace, key)
            self._delete_file(candidate)
        return sqlite_dropped

    def cleanup_quarantine(self, max_age_seconds: int = 86400 * 7) -> int:
        """Remove quarantined files older than ``max_age_seconds`` (default 7 days)."""
        quarantine_dir = self._file_root / "_quarantine"
        if not quarantine_dir.exists():
            return 0
        removed = 0
        cutoff = time.time() - max_age_seconds
        for path in quarantine_dir.iterdir():
            if path.is_file() and path.stat().st_mtime < cutoff:
                try:
                    path.unlink()
                    removed += 1
                except OSError as exc:
                    logger.warning(
                        "unified_cache failed to remove quarantined file %s: %s", path, exc
                    )
        return removed

    def size(self) -> int:
        """Return the number of live entries known to the routing index."""
        return len(self.keys_with_prefix(""))

    def routing_of(self, key: str) -> dict[str, Any] | None:
        """Return the routing record for ``key`` (debug / observability)."""
        return self._read_routing(key)

    def prune_oldest(self, count: int, *, preserve_priority: CachePriority | None = None) -> int:
        """Remove the ``count`` oldest entries, optionally skipping priority."""
        if count <= 0:
            return 0
        cutoff_rank = (
            PRIORITY_RANK[preserve_priority.value] if preserve_priority is not None else -1
        )
        sqlite_deleted = self._prune_sqlite_oldest(count, cutoff_rank=cutoff_rank)
        file_deleted = self._prune_file_oldest(count, cutoff_rank=cutoff_rank)
        return sqlite_deleted + file_deleted

    def _prune_sqlite_oldest(self, count: int, cutoff_rank: int) -> int:
        keys = self.keys_with_prefix("")
        sampled: list[tuple[float, str, int]] = []
        for key in keys:
            record = self._read_routing(key)
            if record is None:
                continue
            if record.get("backend") != Backend.SQLITE.value:
                continue
            priority_rank = PRIORITY_RANK.get(record.get("priority", CachePriority.NORMAL.value), 1)
            if priority_rank >= cutoff_rank:
                continue
            sampled.append((float(record.get("created_at", 0)), key, priority_rank))
        sampled.sort(key=lambda item: item[0])
        victim_keys = [item[1] for item in sampled[:count]]
        removed = 0
        for key in victim_keys:
            if self.delete(key):
                removed += 1
        return removed

    def _prune_file_oldest(self, count: int, cutoff_rank: int) -> int:
        keys = self.keys_with_prefix("")
        sampled: list[tuple[float, str, int]] = []
        for key in keys:
            record = self._read_routing(key)
            if record is None:
                continue
            if record.get("backend") != Backend.FILE.value:
                continue
            priority_rank = PRIORITY_RANK.get(record.get("priority", CachePriority.NORMAL.value), 1)
            if priority_rank >= cutoff_rank:
                continue
            sampled.append((float(record.get("created_at", 0)), key, priority_rank))
        sampled.sort(key=lambda item: item[0])
        victim_keys = [item[1] for item in sampled[:count]]
        removed = 0
        for key in victim_keys:
            if self.delete(key):
                removed += 1
        return removed

    def priority_queue(self) -> list[dict[str, Any]]:
        """Return a stage-partitioned view of the cache sorted by priority and age."""
        entries: list[dict[str, Any]] = []
        for key in self.keys_with_prefix(""):
            record = self._read_routing(key)
            if record is None:
                continue
            namespace = _parse_namespace(key)
            entries.append(
                {
                    "key": key,
                    "namespace": namespace,
                    "backend": record.get("backend"),
                    "priority": record.get("priority", CachePriority.NORMAL.value),
                    "size_bytes": record.get("size_bytes", 0),
                    "created_at": record.get("created_at", 0.0),
                }
            )
        entries.sort(
            key=lambda entry: (
                PRIORITY_RANK.get(entry["priority"], 1),
                -(float(entry["created_at"])),
            )
        )
        return entries

    def partition_by_stage(self) -> dict[str, list[dict[str, Any]]]:
        """Group cache entries by stage namespace for stage-aware eviction."""
        partition: dict[str, list[dict[str, Any]]] = {}
        for entry in self.priority_queue():
            namespace = entry.get("namespace", "unknown")
            partition.setdefault(namespace, []).append(entry)
        return partition

    def coalesce(self) -> CoalescingCacheWrapper:
        return self._coalesce

    def close(self) -> None:
        """Close underlying executors and backing stores."""
        self._coalesce.close()
        self._refresh_executor.shutdown(wait=False)
        self._sqlite.close_all()

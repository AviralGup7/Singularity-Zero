"""Unified cache facade routing structured data to SQLite and blobs to disk.

Provides a single key space over the legacy ``PersistentCache`` (SQLite WAL)
and on-disk JSON / blob storage. Eliminates the coherence gap between
``src.pipeline.cache`` and ``src.pipeline.cache_backend`` by recording every
write in a routing index so the facade always knows which backend holds the
bytes for a given key.
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import json
import os
import tempfile
import threading
import time
from collections.abc import Awaitable, Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.cache_backend import PersistentCache

logger = get_pipeline_logger(__name__)


class Backend(StrEnum):
    SQLITE = "sqlite"
    FILE = "file"


class CachePriority(StrEnum):
    NORMAL = "normal"
    TRANSIENT = "transient"
    CRITICAL = "critical"


class TTLMode(StrEnum):
    HARD_TTL = "hard_ttl"
    STALE_WHILE_REVALIDATE = "stale_while_revalidate"


@dataclass
class NamespaceRouting:
    default_backend: Backend
    default_priority: CachePriority
    split_threshold_bytes: int | None = None


_NAMESPACE_ROUTING: dict[str, NamespaceRouting] = {
    "resume": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.CRITICAL
    ),
    "probe": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
    ),
    "subdomain": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
    ),
    "tool_output": NamespaceRouting(
        default_backend=Backend.FILE, default_priority=CachePriority.TRANSIENT
    ),
    "screenshot": NamespaceRouting(
        default_backend=Backend.FILE, default_priority=CachePriority.TRANSIENT
    ),
    "http_response": NamespaceRouting(
        default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
    ),
}

NAMESPACE_ROUTING = _NAMESPACE_ROUTING

PRIORITY_RANK: dict[str, int] = {
    CachePriority.TRANSIENT.value: 0,
    CachePriority.NORMAL.value: 1,
    CachePriority.CRITICAL.value: 2,
}

ROUTING_PREFIX = "__route__:"
DATA_PREFIX = "__data__:"


def _parse_namespace(key: str) -> str:
    return key.split(":", 1)[0] if ":" in key else key


def _resolve_routing(namespace: str, strict: bool = False) -> NamespaceRouting:
    if namespace in _NAMESPACE_ROUTING:
        return _NAMESPACE_ROUTING[namespace]
    return NamespaceRouting(default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL)


# Module-level constant aliases used throughout unified_cache
_DEFAULT_ROUTING = NamespaceRouting(
    default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL
)
_ROUTING_PREFIX = ROUTING_PREFIX
_DATA_PREFIX = DATA_PREFIX


class CacheKeyNormalizer:
    """Normalize cache keys to enforce canonical form.

    Applied rules (in order):
    1. Strip trailing slashes.
    2. Lowercase the entire key.
    3. Normalize scheme: ``http://`` → ``https://``.
    4. Normalize ``www.`` prefix: ``www.example.com`` → ``example.com``.
    """

    @staticmethod
    def normalize(key: str) -> str:
        key = key.rstrip("/")
        key = key.lower()
        if key.startswith("http://"):
            key = "https://" + key[7:]
        if key.startswith("https://www."):
            key = "https://" + key[12:]
        return key

    @staticmethod
    def path_to_key(path: Path) -> str:
        normalized = str(path).replace("\\", "/").rstrip("/").lower()
        return f"legacy_path:{normalized}"


def _hash_key(key: str) -> str:
    """Return a stable 64-hex SHA-256 of ``key`` for filesystem paths."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` using a tempfile in the same dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, str(path))
        tmp_path = ""
    except Exception:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError as exc:
                logger.warning("Operation failed in unified_cache.py: %s", exc, exc_info=True)  # noqa: BLE001
        raise


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
    """

    def __init__(
        self,
        *,
        sqlite_backend: PersistentCache | None = None,
        file_root: Path | str | None = None,
        strict_namespaces: bool = False,
        max_coalesce_workers: int = 8,
    ) -> None:
        self._sqlite = sqlite_backend if sqlite_backend is not None else PersistentCache()
        if file_root is None:
            default_dir = (
                Path(__file__).resolve().parent.parent / "output" / "cache" / "unified_blobs"
            )
            self._file_root = default_dir
        else:
            self._file_root = Path(file_root)
        self._file_root.mkdir(parents=True, exist_ok=True)
        self._strict = strict_namespaces
        self._lock = threading.RLock()
        # Hard cap at 16 threads to prevent resource exhaustion
        capped_workers = min(max_coalesce_workers, 16)
        self._coalesce = CoalescingCacheWrapper(self, max_workers=capped_workers)
        self._refresh_executor = ThreadPoolExecutor(
            max_workers=max(1, capped_workers // 2), thread_name_prefix="cache-refresh"
        )

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
        try:
            if path.exists():
                path.unlink()
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

    def size(self) -> int:
        """Return the number of live entries known to the routing index."""
        return len(self.keys_with_prefix(""))

    def routing_of(self, key: str) -> dict[str, Any] | None:
        """Return the routing record for ``key`` (debug / observability)."""
        return self._read_routing(key)

    def prune_oldest(self, count: int, *, preserve_priority: CachePriority | None = None) -> int:
        """Remove the ``count`` oldest entries, optionally skipping priority.

        ``preserve_priority`` prevents eviction of entries at or above the
        given rank; only lower-priority entries are considered. CRITICAL
        entries are therefore protected when ``preserve_priority=CachePriority.CRITICAL``.
        """
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


class _PendingRefresh:
    """Tracks a pending stale-while-revalidate background refresh."""

    __slots__ = ("key", "task", "started_at")

    def __init__(self, key: str, task: asyncio.Task[None]) -> None:
        self.key = key
        self.task = task
        self.started_at = time.time()


class CoalescingCacheWrapper:
    """Deduplicate concurrent cache misses by key with an async lock registry.

    Callers that hit an expired or missing entry coordinate through
    ``run_with_coalescing``; the first caller executes ``loader`` while
    waiters block on the same key-level event until the result is ready.
    This eliminates duplicate subprocess spawns when parallel stages
    request the same URL simultaneously.
    """

    def __init__(self, unified: UnifiedCache, *, max_workers: int = 8) -> None:
        self._unified = unified
        self._lock_registry: dict[str, asyncio.Lock] = {}
        self._registry_lock = threading.Lock()
        # Hard cap at 16 threads to prevent resource exhaustion
        capped_workers = min(max_workers, 16)
        self._executor = ThreadPoolExecutor(
            max_workers=capped_workers, thread_name_prefix="cache-coalesce"
        )
        self._pending_refreshes: dict[str, _PendingRefresh] = {}
        self._pending_lock = threading.Lock()
        self._bg_refresh_callbacks: list[Callable[[str, Any], Awaitable[None]]] = []

        self._metrics = {
            "coalesced_hits": 0,
            "deduplicated_calls": 0,
            "refreshes_triggered": 0,
            "refreshes_completed": 0,
        }
        self._metrics_lock = threading.Lock()

    def register_background_refresh(self, callback: Callable[[str, Any], Awaitable[None]]) -> None:
        self._bg_refresh_callbacks.append(callback)

    def _get_key_lock(self, key: str) -> asyncio.Lock:
        with self._registry_lock:
            lock = self._lock_registry.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._lock_registry[key] = lock
            return lock

    def _snapshot_metrics(self) -> dict[str, Any]:
        with self._metrics_lock:
            return dict(self._metrics)

    def run_with_coalescing(
        self,
        key: str,
        loader: Callable[[], Any],
        *,
        ttl: int | None = None,
        priority: CachePriority = CachePriority.NORMAL,
        ttl_mode: TTLMode = TTLMode.HARD_TTL,
        stale_threshold_hours: int = 24,
        refresh_ttl: int | None = None,
    ) -> Any:
        """Return a cached value, loading through ``loader`` if necessary.

        ``loader`` **must not** be a coroutine; use a sync wrapper when the
        real work is async so that ``run_in_executor`` has something to run.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            coro = self._coalesced_sync(
                key,
                loader,
                ttl=ttl,
                priority=priority,
                ttl_mode=ttl_mode,
                stale_threshold_hours=stale_threshold_hours,
                refresh_ttl=refresh_ttl,
            )
            return asyncio.run(coro)

        lock = self._get_key_lock(key)

        async def _coalesced() -> Any:
            async with lock:
                return await self._execute_coalesced(
                    key,
                    loader,
                    loop=loop,
                    ttl=ttl,
                    priority=priority,
                    ttl_mode=ttl_mode,
                    stale_threshold_hours=stale_threshold_hours,
                    refresh_ttl=refresh_ttl,
                )

        return loop.run_until_complete(_coalesced())

    async def _coalesced_sync(
        self,
        key: str,
        loader: Callable[[], Any],
        *,
        ttl: int | None,
        priority: CachePriority,
        ttl_mode: TTLMode,
        stale_threshold_hours: int,
        refresh_ttl: int | None,
    ) -> Any:
        return await self._execute_coalesced(
            key,
            loader,
            loop=asyncio.get_running_loop(),
            ttl=ttl,
            priority=priority,
            ttl_mode=ttl_mode,
            stale_threshold_hours=stale_threshold_hours,
            refresh_ttl=refresh_ttl,
        )

    async def _execute_coalesced(
        self,
        key: str,
        loader: Callable[[], Any],
        *,
        loop: asyncio.AbstractEventLoop,
        ttl: int | None,
        priority: CachePriority,
        ttl_mode: TTLMode,
        stale_threshold_hours: int,
        refresh_ttl: int | None,
    ) -> Any:
        lock = self._get_key_lock(key)
        async with lock:
            cached = self._unified.get(key)
            if cached is not None and ttl_mode == TTLMode.HARD_TTL:
                return cached
            if cached is not None and ttl_mode == TTLMode.STALE_WHILE_REVALIDATE:
                if response_cache_fresh(cached, stale_threshold_hours):
                    return cached
                background = self._maybe_kick_off_refresh(
                    key, cached, loader, refresh_ttl, priority
                )
                if background is not None:
                    return cached
            value = await loop.run_in_executor(self._executor, loader)
            self._unified.set(
                key,
                value,
                ttl=ttl,
                priority=priority,
                ttl_mode=ttl_mode,
                stale_threshold_hours=stale_threshold_hours
                if ttl_mode == TTLMode.STALE_WHILE_REVALIDATE
                else None,
            )
            with self._metrics_lock:
                self._metrics["coalesced_hits"] += 1
            return value

    def _maybe_kick_off_refresh(
        self,
        key: str,
        cached: Any,
        loader: Callable[[], Any],
        refresh_ttl: int | None,
        priority: CachePriority,
    ) -> asyncio.Task[None] | None:
        with self._pending_lock:
            pending = self._pending_refreshes.get(key)
            if pending is not None and not pending.task.done():
                self._metrics["deduplicated_calls"] += 1
                return pending.task
            task: asyncio.Task[None] | None = None

            def _kick() -> None:
                nonlocal task
                current = asyncio.get_running_loop()
                task = current.create_task(
                    self._background_refresh(key, cached, loader, refresh_ttl, priority)
                )

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return None
            loop.call_soon(_kick)
            if task is not None:
                self._pending_refreshes[key] = _PendingRefresh(key, task)
                self._metrics["refreshes_triggered"] += 1
                task.add_done_callback(lambda _: self._pending_refreshes.pop(key, None))
                return task
        return None

    async def _background_refresh(
        self,
        key: str,
        stale: Any,
        loader: Callable[[], Any],
        refresh_ttl: int | None,
        priority: CachePriority,
    ) -> None:
        loop = asyncio.get_running_loop()
        try:
            fresh = await loop.run_in_executor(self._executor, loader)
        except Exception as exc:
            logger.debug("Background refresh failed for %s: %s", key, exc)
            return
        self._unified.set(
            key,
            fresh,
            ttl=refresh_ttl,
            priority=priority,
            ttl_mode=TTLMode.STALE_WHILE_REVALIDATE,
        )
        for callback in list(self._bg_refresh_callbacks):
            try:
                await callback(key, fresh)
            except Exception as exc:
                logger.debug("Background refresh callback failed for %s: %s", key, exc)
        with self._metrics_lock:
            self._metrics["refreshes_completed"] += 1

    def get_metrics(self) -> dict[str, Any]:
        return self._snapshot_metrics()

    def close(self) -> None:
        with self._pending_lock:
            for pending in self._pending_refreshes.values():
                if not pending.task.done():
                    pending.task.cancel()
            self._pending_refreshes.clear()
        with self._registry_lock:
            self._lock_registry.clear()
        self._executor.shutdown(wait=False)


def response_cache_fresh(
    record: dict[str, Any],
    ttl_hours: int,
    content_hash: str | None = None,
) -> bool:
    if ttl_hours <= 0:
        return False
    try:
        fetched_at = float(record.get("cached_at_epoch", 0))
    except (TypeError, ValueError):
        return False
    if fetched_at <= 0:
        return False
    if content_hash and record.get("content_hash") != content_hash:
        return False
    return (time.time() - fetched_at) < ttl_hours * 3600


_unified_cache = UnifiedCache()

atexit.register(_unified_cache.close)


def cache_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("enabled", True))


def load_cached_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
        return dict(json.loads(raw.decode("utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def save_cached_json(
    path: Path, payload: dict[str, Any] | list[Any], *, compress: bool = True
) -> None:
    data = json.dumps(payload).encode("utf-8")
    _atomic_write_bytes(path, data)


def load_cached_set(path: Path) -> set[str]:
    loaded = load_cached_json(path)
    return set(loaded) if isinstance(loaded, list) else set()


def save_cached_set(path: Path, items: Iterable[str], *, compress: bool = True) -> None:
    save_cached_json(path, list(items), compress=compress)

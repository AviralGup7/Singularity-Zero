"""CoalescingCacheWrapper — deduplicate concurrent cache misses."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from src.pipeline.unified_cache.models import CachePriority, TTLMode
from src.pipeline.unified_cache.policies import response_cache_fresh

if TYPE_CHECKING:
    from src.pipeline.unified_cache.storage import UnifiedCache

logger = logging.getLogger(__name__)


class _PendingRefresh:
    """Tracks a pending stale-while-revalidate background refresh."""

    __slots__ = ("key", "task", "started_at")

    def __init__(self, key: str, task: asyncio.Task[None]) -> None:
        self.key = key
        self.task = task
        import time

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
        self._lock_registry_max = 4096
        capped_workers = min(max_workers, 16)
        self._executor = ThreadPoolExecutor(
            max_workers=capped_workers, thread_name_prefix="cache-coalesce"
        )
        self._pending_refreshes: dict[str, _PendingRefresh] = {}
        self._pending_lock = threading.Lock()
        self._pending_refreshes_max = 2048
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
                if len(self._lock_registry) >= self._lock_registry_max:
                    self._lock_registry.pop(next(iter(self._lock_registry)))
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
        """Return a cached value, loading through ``loader`` if necessary."""
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
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return None
            try:
                from src.core.concurrency_governor import get_governor

                if not get_governor().allow("cache_refresh"):
                    logger.debug(
                        "Cache refresh for %s deferred: global governor limit reached",
                        key,
                    )
                    return None
            except ImportError:
                pass
            task = loop.create_task(
                self._background_refresh(key, cached, loader, refresh_ttl, priority)
            )
            task.add_done_callback(self._make_governor_release_callback())
            with self._pending_lock:
                if len(self._pending_refreshes) >= self._pending_refreshes_max:
                    self._pending_refreshes.pop(next(iter(self._pending_refreshes)))
            self._pending_refreshes[key] = _PendingRefresh(key, task)
            self._metrics["refreshes_triggered"] += 1
            task.add_done_callback(lambda _: self._pending_refreshes.pop(key, None))
            return task

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

    @staticmethod
    def _make_governor_release_callback() -> Callable[[asyncio.Task[None]], None]:
        """Return a done callback that releases the global governor slot."""

        def _release(task: asyncio.Task[None]) -> None:
            try:
                from src.core.concurrency_governor import get_governor

                get_governor().release("cache_refresh")
            except ImportError:
                pass

        return _release

    def close(self) -> None:
        with self._pending_lock:
            for pending in self._pending_refreshes.values():
                if not pending.task.done():
                    pending.task.cancel()
            self._pending_refreshes.clear()
        with self._registry_lock:
            self._lock_registry.clear()
        self._executor.shutdown(wait=False)

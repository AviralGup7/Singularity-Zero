"""Resource pool management for the concurrent execution engine.

Provides:
    - ResourcePool: bounded semaphore pool for a single resource type
    - ResourcePoolManager: multi-pool coordinator with dynamic sizing and health monitoring
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PoolHealth:
    """Snapshot of a resource pool's health metrics."""

    pool_name: str
    max_concurrent: int
    current_usage: int
    available: int
    total_acquisitions: int = 0
    total_timeouts: int = 0
    total_errors: int = 0
    avg_wait_time_seconds: float = 0.0
    last_health_check: float = field(default_factory=time.monotonic)

    @property
    def utilisation_pct(self) -> float:
        """Current utilisation as a percentage (0-100)."""
        if self.max_concurrent == 0:
            return 0.0
        return (self.current_usage / self.max_concurrent) * 100.0

    @property
    def is_healthy(self) -> bool:
        """Pool is considered healthy if timeout rate is below 10%."""
        total = self.total_acquisitions + self.total_timeouts
        if total == 0:
            return True
        timeout_rate = self.total_timeouts / total
        return timeout_rate < 0.10


class ResourcePool:
    """Bounded semaphore pool for a single resource type.

    Uses asyncio.Semaphore to enforce strict concurrency limits.
    Supports dynamic resizing and health tracking.

    Attributes:
        name: Unique identifier for this pool.
        max_concurrent: Current hard limit on concurrent holders.
        acquire_timeout: Seconds to wait before raising TimeoutError.
    """

    def __init__(
        self,
        name: str,
        max_concurrent: int = 10,
        acquire_timeout: float = 30.0,
    ) -> None:
        self.name = name
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._acquire_timeout = acquire_timeout
        self._health = PoolHealth(
            pool_name=name, max_concurrent=max_concurrent, current_usage=0, available=max_concurrent
        )
        self._lock = asyncio.Lock()
        self._closed = False
        self._wait_times: list[float] = []

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def current_usage(self) -> int:
        return self._health.current_usage

    @property
    def available(self) -> int:
        return max(0, self._max_concurrent - self._health.current_usage)

    @property
    def health(self) -> PoolHealth:
        return self._health

    async def resize(self, new_max: int) -> None:
        """Dynamically change the pool size.

        Increasing adds permits; decreasing removes permits (waits for
        in-use permits to be released before enforcing the new limit).

        Args:
            new_max: New maximum concurrent count (must be >= 1).
        """
        if new_max < 1:
            raise ValueError("max_concurrent must be >= 1")

        async with self._lock:
            if new_max > self._max_concurrent:
                added = new_max - self._max_concurrent
                for _ in range(added):
                    self._semaphore.release()
            self._max_concurrent = new_max
            self._health.max_concurrent = new_max
            logger.info("Resource pool '%s' resized to %d", self.name, new_max)

    async def acquire(self, timeout: float | None = None) -> bool:
        """Acquire a resource permit from the pool.

        Args:
            timeout: Override the default acquire timeout.

        Returns:
            True if the permit was acquired.

        Raises:
            TimeoutError: If the permit could not be acquired within the timeout.
            RuntimeError: If the pool has been closed.
        """
        if self._closed:
            raise RuntimeError(f"Resource pool '{self.name}' is closed")

        effective_timeout = timeout if timeout is not None else self._acquire_timeout
        start = time.monotonic()
        self._health.total_acquisitions += 1

        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=effective_timeout)
            self._health.current_usage += 1
            wait_time = time.monotonic() - start
            self._wait_times.append(wait_time)
            if len(self._wait_times) > 1000:
                self._wait_times = self._wait_times[-500:]
            self._health.avg_wait_time_seconds = sum(self._wait_times) / len(self._wait_times)
            return True
        except TimeoutError:
            self._health.total_timeouts += 1
            logger.warning(
                "Resource pool '%s' acquire timed out after %.1fs (usage: %d/%d)",
                self.name,
                effective_timeout,
                self._health.current_usage,
                self._max_concurrent,
            )
            raise

    async def release(self) -> None:
        """Release a resource permit back to the pool."""
        if self._health.current_usage > 0:
            self._health.current_usage -= 1
            self._semaphore.release()
            logger.debug(
                "Resource pool '%s' released (usage: %d/%d)",
                self.name,
                self._health.current_usage,
                self._max_concurrent,
            )

    async def health_check(self) -> PoolHealth:
        """Run a health check and return the current health snapshot."""
        self._health.last_health_check = time.monotonic()
        self._health.available = self.available
        return self._health

    async def close(self) -> None:
        """Close the pool, preventing further acquisitions."""
        self._closed = True
        logger.info("Resource pool '%s' closed", self.name)

    async def __aenter__(self) -> ResourcePool:
        await self.acquire()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self._health.total_errors += 1
        await self.release()


class ResourcePoolManager:
    """Coordinates multiple resource pools with dynamic sizing and health monitoring.

    Provides a central registry for resource pools, dynamic pool sizing based
    on system load, and periodic health monitoring.

    Attributes:
        pools: Mapping of pool name -> ResourcePool.
    """

    def __init__(self) -> None:
        self._pools: dict[str, ResourcePool] = {}
        self._monitor_task: asyncio.Task[None] | None = None
        self._monitoring = False
        self._lock = asyncio.Lock()

    @property
    def pools(self) -> dict[str, ResourcePool]:
        return dict(self._pools)

    def register_pool(self, pool: ResourcePool) -> None:
        """Register a resource pool with the manager.

        Args:
            pool: The ResourcePool instance to register.
        """
        self._pools[pool.name] = pool
        logger.info(
            "Registered resource pool '%s' (max_concurrent=%d)", pool.name, pool.max_concurrent
        )

    def get_pool(self, name: str) -> ResourcePool:
        """Retrieve a pool by name.

        Args:
            name: Pool identifier.

        Returns:
            The ResourcePool instance.

        Raises:
            KeyError: If the pool does not exist.
        """
        if name not in self._pools:
            raise KeyError(
                f"Resource pool '{name}' not found. Available: {list(self._pools.keys())}"
            )
        return self._pools[name]

    async def acquire_multi(self, resource_types: list[str]) -> list[ResourcePool]:
        """Acquire permits from multiple pools atomically.

        Acquires in sorted order to prevent deadlocks. If any acquisition
        fails, all previously acquired permits are released.

        Args:
            resource_types: List of pool names to acquire from.

        Returns:
            List of acquired ResourcePool instances.

        Raises:
            TimeoutError: If any pool acquisition times out.
        """
        sorted_types = sorted(set(resource_types))
        acquired: list[ResourcePool] = []

        try:
            for pool_name in sorted_types:
                pool = self.get_pool(pool_name)
                await pool.acquire()
                acquired.append(pool)
            return acquired
        except TimeoutError:
            for pool in acquired:
                await pool.release()
            raise

    async def release_multi(self, pools: list[ResourcePool]) -> None:
        """Release permits back to multiple pools.

        Args:
            pools: List of ResourcePool instances to release.
        """
        for pool in pools:
            await pool.release()

    async def dynamic_resize(self, pool_name: str, system_load: float) -> None:
        """Dynamically resize a pool based on system load.

        System load is a value between 0.0 and 1.0. High load reduces pool
        size to prevent overload; low load increases it for throughput.

        Args:
            pool_name: Pool to resize.
            system_load: Current system load (0.0 = idle, 1.0 = saturated).
        """
        pool = self.get_pool(pool_name)

        if system_load > 0.8:
            new_size = max(
                pool.min_size if hasattr(pool, "min_size") else 1, pool.max_concurrent // 2
            )
        elif system_load < 0.3:
            new_size = min(
                pool.max_size if hasattr(pool, "max_size") else pool.max_concurrent * 2,
                pool.max_concurrent * 2,
            )
        else:
            return

        await pool.resize(new_size)
        logger.info(
            "Dynamic resize of pool '%s': %d -> %d (load=%.2f)",
            pool_name,
            pool.max_concurrent,
            new_size,
            system_load,
        )

    async def health_check_all(self) -> dict[str, PoolHealth]:
        """Run health checks on all registered pools.

        Returns:
            Dict mapping pool name -> PoolHealth snapshot.
        """
        results: dict[str, PoolHealth] = {}
        for name, pool in self._pools.items():
            results[name] = await pool.health_check()
        return results

    async def start_monitoring(
        self,
        interval_seconds: float = 60.0,
        load_callback: Callable[[], Awaitable[float]] | None = None,
    ) -> None:
        """Start periodic health monitoring in the background.

        Args:
            interval_seconds: Seconds between health checks.
            load_callback: Optional async callable returning current system load (0.0-1.0).
        """
        if self._monitoring:
            return

        self._monitoring = True

        async def _monitor_loop() -> None:
            while self._monitoring:
                try:
                    health = await self.health_check_all()
                    for name, h in health.items():
                        if not h.is_healthy:
                            logger.warning("Resource pool '%s' is unhealthy: %s", name, h)

                    if load_callback:
                        load = await load_callback()
                        for name in self._pools:
                            await self.dynamic_resize(name, load)
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception("Error during pool health monitoring")

                await asyncio.sleep(interval_seconds)

        self._monitor_task = asyncio.create_task(_monitor_loop(), name="resource-pool-monitor")

    async def stop_monitoring(self) -> None:
        """Stop the background monitoring task."""
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

    async def close_all(self) -> None:
        """Close all registered pools and stop monitoring."""
        await self.stop_monitoring()
        for pool in self._pools.values():
            await pool.close()
        self._pools.clear()

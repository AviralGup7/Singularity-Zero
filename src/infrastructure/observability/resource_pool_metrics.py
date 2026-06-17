"""Resource pool metrics for thread and connection pool monitoring.

Tracks utilization, saturation, and exhaustion of concurrency pools
(thread pools, async task pools, connection pools) to help operators
identify bottlenecks before they cause cascading failures.

Usage:
    from src.infrastructure.observability.resource_pool_metrics import ResourcePoolMetrics

    pool_metrics = ResourcePoolMetrics()
    pool_metrics.record_pool_state(
        pool_name="db_pool",
        active=5, idle=3, max_size=10, waiting=0
    )
"""

from __future__ import annotations

import threading


class ResourcePoolMetrics:
    """Tracks resource pool utilization and saturation.

    Monitors:
    - Active/idle/waiting counts per pool
    - Pool utilization ratio (active/max)
    - Wait time for pool access
    - Timeout events
    - Pool exhaustion events
    """

    def __init__(self) -> None:
        self._pools: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def record_pool_state(
        self,
        pool_name: str,
        active: int,
        idle: int,
        max_size: int,
        waiting: int = 0,
    ) -> None:
        """Record current pool state.

        Args:
            pool_name: Identifier for the pool.
            active: Currently active connections/threads.
            idle: Currently idle connections/threads.
            max_size: Maximum pool capacity.
            waiting: Number of callers waiting for a resource.
        """
        utilization = active / max_size if max_size > 0 else 0.0
        saturation = (active + waiting) / max_size if max_size > 0 else 0.0

        with self._lock:
            self._pools[pool_name] = {
                "active": active,
                "idle": idle,
                "max_size": max_size,
                "waiting": waiting,
                "utilization": utilization,
                "saturation": saturation,
            }

        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            labels = {"pool": pool_name}

            metrics.gauge("pool_active", "Active resources in pool", labels=labels).set(active)
            metrics.gauge("pool_idle", "Idle resources in pool", labels=labels).set(idle)
            metrics.gauge("pool_max_size", "Maximum pool capacity", labels=labels).set(max_size)
            metrics.gauge("pool_waiting", "Callers waiting for a resource", labels=labels).set(
                waiting
            )
            metrics.gauge(
                "pool_utilization_ratio",
                "Pool utilization ratio (active/max_size)",
                labels=labels,
            ).set(utilization)
            metrics.gauge(
                "pool_saturation_ratio",
                "Pool saturation ratio ((active+waiting)/max_size)",
                labels=labels,
            ).set(saturation)
        except Exception:
            pass

    def record_wait_time(self, pool_name: str, wait_seconds: float) -> None:
        """Record time spent waiting for a pool resource.

        Args:
            pool_name: Identifier for the pool.
            wait_seconds: Time spent waiting in seconds.
        """
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.histogram(
                "pool_wait_time_seconds",
                "Time spent waiting for a pool resource",
                buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
                labels={"pool": pool_name},
            ).observe(wait_seconds)
        except Exception:
            pass

    def record_timeout(self, pool_name: str) -> None:
        """Record a pool access timeout event.

        Args:
            pool_name: Identifier for the pool.
        """
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.counter(
                "pool_timeouts_total",
                "Total pool access timeout events",
                labels={"pool": pool_name},
            ).inc()
        except Exception:
            pass

    def record_exhaustion(self, pool_name: str) -> None:
        """Record a pool exhaustion event (saturation >= 100%).

        Args:
            pool_name: Identifier for the pool.
        """
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.counter(
                "pool_exhaustion_events_total",
                "Total pool exhaustion events",
                labels={"pool": pool_name},
            ).inc()
        except Exception:
            pass

    def get_pool_state(self, pool_name: str) -> dict[str, float] | None:
        """Get cached pool state.

        Args:
            pool_name: Pool identifier.

        Returns:
            Pool state dict or None if not tracked.
        """
        with self._lock:
            return self._pools.get(pool_name)

    def get_all_pools(self) -> dict[str, dict[str, float]]:
        """Get all tracked pool states.

        Returns:
            Dict of pool_name -> state.
        """
        with self._lock:
            return dict(self._pools)


def collect_thread_pool_metrics(pool_name: str = "default") -> None:
    """Collect metrics from the current thread pool state.

    Reads threading module state to report on thread utilization.
    Should be called periodically via a background task.
    """
    try:
        import threading as _threading

        active_count = _threading.active_count()
        main_thread = _threading.main_thread()
        daemon_count = sum(1 for t in _threading.enumerate() if t.daemon)
        non_daemon_count = active_count - daemon_count

        from src.infrastructure.observability.metrics import get_metrics

        metrics = get_metrics()
        labels = {"pool": pool_name}

        metrics.gauge("thread_pool_active_count", "Number of active threads", labels=labels).set(
            active_count
        )
        metrics.gauge("thread_pool_daemon_count", "Number of daemon threads", labels=labels).set(
            daemon_count
        )
        metrics.gauge(
            "thread_pool_non_daemon_count", "Number of non-daemon threads", labels=labels
        ).set(non_daemon_count)
    except Exception:
        pass


def collect_asyncio_pool_metrics(pool_name: str = "default") -> None:
    """Collect metrics from the current asyncio event loop.

    Reports on task counts and event loop health.
    Should be called periodically via a background task.
    """
    try:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        tasks = asyncio.all_tasks(loop)

        pending = sum(1 for t in tasks if not t.done())
        done = sum(1 for t in tasks if t.done())
        total = len(tasks)

        from src.infrastructure.observability.metrics import get_metrics

        metrics = get_metrics()
        labels = {"pool": pool_name}

        metrics.gauge(
            "asyncio_tasks_pending", "Number of pending asyncio tasks", labels=labels
        ).set(pending)
        metrics.gauge("asyncio_tasks_done", "Number of completed asyncio tasks", labels=labels).set(
            done
        )
        metrics.gauge("asyncio_tasks_total", "Total asyncio tasks", labels=labels).set(total)
    except Exception:
        pass

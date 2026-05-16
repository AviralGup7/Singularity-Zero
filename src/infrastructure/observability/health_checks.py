"""Health check system for the cyber security test pipeline.

Provides component-level health checks, aggregate health status,
dependency health tracking, and health check history.

Usage:
    from src.infrastructure.observability.health_checks import get_health_checker

    checker = get_health_checker()
    checker.register("redis", check_redis_health)
    status = await checker.check_all()
    print(status.overall_status)
"""

import asyncio
import json
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from src.infrastructure.observability.config import get_config


class HealthStatus(StrEnum):
    """Aggregate health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentStatus(StrEnum):
    """Individual component health status."""

    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component."""

    name: str
    status: ComponentStatus = ComponentStatus.UNKNOWN
    message: str = ""
    last_check: float = 0.0
    response_time_ms: float = 0.0
    consecutive_failures: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "last_check": self.last_check,
            "response_time_ms": round(self.response_time_ms, 2),
            "consecutive_failures": self.consecutive_failures,
            "metadata": self.metadata,
        }


@dataclass
class HealthCheckResult:
    """Result of a health check operation."""

    timestamp: float = field(default_factory=time.time)
    overall_status: HealthStatus = HealthStatus.UNKNOWN
    components: dict[str, ComponentHealth] = field(default_factory=dict)
    duration_ms: float = 0.0
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "timestamp": self.timestamp,
            "overall_status": self.overall_status.value,
            "components": {n: h.to_dict() for n, h in self.components.items()},
            "duration_ms": round(self.duration_ms, 2),
            "version": self.version,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)


@dataclass
class HealthHistoryEntry:
    """A single entry in the health check history."""

    timestamp: float
    status: HealthStatus
    component_statuses: dict[str, ComponentStatus]


CheckFunc = Callable[[], Awaitable[ComponentHealth]]


class HealthChecker:
    """Manages health checks for all pipeline components."""

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        failure_threshold: int = 3,
        history_size: int = 100,
        version: str = "1.0.0",
    ) -> None:
        """Initialize the health checker.

        Args:
            timeout_seconds: Timeout for individual health checks.
            failure_threshold: Consecutive failures before marking unhealthy.
            history_size: Number of historical entries to retain.
            version: Application version string.
        """
        self._checks: dict[str, CheckFunc] = {}
        self._components: dict[str, ComponentHealth] = {}
        self._history: deque[HealthHistoryEntry] = deque(maxlen=history_size)
        self._timeout = timeout_seconds
        self._failure_threshold = failure_threshold
        self._version = version
        self._last_result: HealthCheckResult | None = None

    def register(self, name: str, check_func: CheckFunc) -> None:
        """Register a health check function for a component."""
        self._checks[name] = check_func
        if name not in self._components:
            self._components[name] = ComponentHealth(name=name)

    def unregister(self, name: str) -> None:
        """Remove a component health check."""
        self._checks.pop(name, None)
        self._components.pop(name, None)

    def get_component(self, name: str) -> ComponentHealth | None:
        """Get the last known health of a component."""
        return self._components.get(name)

    async def check_component(self, name: str) -> ComponentHealth:
        """Run health check for a single component."""
        check_func = self._checks.get(name)
        if check_func is None:
            return ComponentHealth(
                name=name,
                status=ComponentStatus.UNKNOWN,
                message=f"No health check registered for component: {name}",
            )

        start = time.monotonic()
        try:
            health = await asyncio.wait_for(check_func(), timeout=self._timeout)
            health.response_time_ms = (time.monotonic() - start) * 1000
            health.last_check = time.time()

            if health.status in (ComponentStatus.UP, ComponentStatus.DEGRADED):
                health.consecutive_failures = 0
            else:
                health.consecutive_failures += 1

        except TimeoutError:
            prev = self._components.get(name, ComponentHealth(name=name))
            health = ComponentHealth(
                name=name,
                status=ComponentStatus.DOWN,
                message=f"Health check timed out after {self._timeout}s",
                last_check=time.time(),
                response_time_ms=(time.monotonic() - start) * 1000,
                consecutive_failures=prev.consecutive_failures + 1,
            )
        except Exception as e:
            prev = self._components.get(name, ComponentHealth(name=name))
            health = ComponentHealth(
                name=name,
                status=ComponentStatus.DOWN,
                message=f"Health check failed: {type(e).__name__}: {e}",
                last_check=time.time(),
                response_time_ms=(time.monotonic() - start) * 1000,
                consecutive_failures=prev.consecutive_failures + 1,
            )

        self._components[name] = health
        return health

    async def check_all(self) -> HealthCheckResult:
        """Run health checks for all registered components concurrently."""
        start = time.monotonic()

        if not self._checks:
            result = HealthCheckResult(
                overall_status=HealthStatus.HEALTHY,
                version=self._version,
            )
            self._last_result = result
            return result

        tasks = [asyncio.create_task(self.check_component(n)) for n in self._checks]
        await asyncio.gather(*tasks, return_exceptions=True)

        duration_ms = (time.monotonic() - start) * 1000
        overall = self._aggregate_status()

        result = HealthCheckResult(
            timestamp=time.time(),
            overall_status=overall,
            components=dict(self._components),
            duration_ms=duration_ms,
            version=self._version,
        )

        self._history.append(
            HealthHistoryEntry(
                timestamp=result.timestamp,
                status=overall,
                component_statuses={n: c.status for n, c in self._components.items()},
            )
        )

        self._last_result = result
        return result

    def _aggregate_status(self) -> HealthStatus:
        """Aggregate component statuses into an overall health status."""
        if not self._components:
            return HealthStatus.HEALTHY

        statuses = [c.status for c in self._components.values()]

        if all(s == ComponentStatus.UP for s in statuses):
            return HealthStatus.HEALTHY

        if any(s == ComponentStatus.DOWN for s in statuses):
            down_count = sum(1 for s in statuses if s == ComponentStatus.DOWN)
            if down_count > len(statuses) // 2:
                return HealthStatus.UNHEALTHY
            return HealthStatus.DEGRADED

        if any(s == ComponentStatus.DEGRADED for s in statuses):
            return HealthStatus.DEGRADED

        return HealthStatus.DEGRADED

    def get_history(self, limit: int = 20) -> list[HealthHistoryEntry]:
        """Get recent health check history."""
        entries = list(self._history)
        return list(reversed(entries))[:limit]

    def get_trend(self) -> dict[str, Any]:
        """Analyze health trends from history."""
        if not self._history:
            return {"trend": "unknown", "entries": 0}
        entries = list(self._history)
        recent = entries[-10:] if len(entries) >= 10 else entries
        healthy_count = sum(1 for e in recent if e.status == HealthStatus.HEALTHY)
        degraded_count = sum(1 for e in recent if e.status == HealthStatus.DEGRADED)
        unhealthy_count = sum(1 for e in recent if e.status == HealthStatus.UNHEALTHY)
        total = len(recent)
        health_ratio = healthy_count / total if total > 0 else 0
        if health_ratio >= 0.9:
            trend = "stable"
        elif health_ratio >= 0.7:
            trend = "degrading"
        else:
            trend = "unstable"
        return {
            "trend": trend,
            "entries": len(entries),
            "health_ratio": round(health_ratio, 3),
            "healthy_count": healthy_count,
            "degraded_count": degraded_count,
            "unhealthy_count": unhealthy_count,
            "latest_status": entries[-1].status.value if entries else "unknown",
        }

    def get_last_result(self) -> HealthCheckResult | None:
        """Get the most recent health check result."""
        return self._last_result

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of current health status."""
        return {
            "overall_status": (
                self._last_result.overall_status.value
                if self._last_result
                else HealthStatus.UNKNOWN.value
            ),
            "component_count": len(self._components),
            "components": {n: c.status.value for n, c in self._components.items()},
            "trend": self.get_trend(),
            "last_check": self._last_result.timestamp if self._last_result else None,
        }


async def _check_redis_health(config: dict[str, Any]) -> ComponentHealth:
    """Check Redis connectivity and health."""
    name = config.get("name", "redis")
    url = config.get("url", "redis://localhost:6379")
    try:
        import redis.asyncio as aioredis
        from typing import Any, cast

        client = aioredis.from_url(url)
        await cast(Any, client.ping())
        info = await cast(Any, client.info("server"))
        await client.aclose()
        rv = info.get("redis_version", "unknown")
        return ComponentHealth(
            name=name,
            status=ComponentStatus.UP,
            message=f"Redis connected (version: {rv})",
            metadata={"version": rv},
        )
    except ImportError:
        return ComponentHealth(
            name=name,
            status=ComponentStatus.UNKNOWN,
            message="Redis client not available",
        )
    except Exception as e:
        return ComponentHealth(
            name=name,
            status=ComponentStatus.DOWN,
            message=f"Redis check failed: {e}",
        )


async def _check_sqlite_health(config: dict[str, Any]) -> ComponentHealth:
    """Check SQLite database health."""
    name = config.get("name", "sqlite")
    path = config.get("path", "pipeline.db")
    try:
        import sqlite3

        conn = sqlite3.connect(path)
        conn.execute("SELECT 1")
        conn.close()
        return ComponentHealth(
            name=name,
            status=ComponentStatus.UP,
            message=f"SQLite database accessible at {path}",
        )
    except Exception as e:
        return ComponentHealth(
            name=name,
            status=ComponentStatus.DOWN,
            message=f"SQLite check failed: {e}",
        )


async def _check_http_health(config: dict[str, Any]) -> ComponentHealth:
    """Check HTTP endpoint health."""
    name = config.get("name", "http")
    url = config.get("url", "http://localhost:8000/health")
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                return ComponentHealth(
                    name=name,
                    status=ComponentStatus.UP,
                    message=f"HTTP endpoint returned {response.status_code}",
                    metadata={"status_code": response.status_code},
                )
            return ComponentHealth(
                name=name,
                status=ComponentStatus.DEGRADED,
                message=f"HTTP endpoint returned {response.status_code}",
                metadata={"status_code": response.status_code},
            )
    except Exception as e:
        return ComponentHealth(
            name=name,
            status=ComponentStatus.DOWN,
            message=f"HTTP check failed: {e}",
        )


_health_checker_instance: HealthChecker | None = None


def get_health_checker() -> HealthChecker:
    """Get the global health checker instance."""
    global _health_checker_instance
    if _health_checker_instance is None:
        config = get_config()
        hc_config = config.health_check
        _health_checker_instance = HealthChecker(
            timeout_seconds=hc_config.timeout_seconds,
            failure_threshold=hc_config.failure_threshold,
            history_size=hc_config.history_size,
        )
    return _health_checker_instance


def register_default_health_checks(checker: HealthChecker | None = None) -> None:
    """Register default health checks for pipeline components."""
    if checker is None:
        checker = get_health_checker()

    async def check_redis() -> ComponentHealth:
        return await _check_redis_health({"name": "redis", "url": "redis://localhost:6379"})

    async def check_sqlite() -> ComponentHealth:
        return await _check_sqlite_health({"name": "sqlite", "path": "pipeline.db"})

    async def check_workers() -> ComponentHealth:
        import multiprocessing

        try:
            worker_count = multiprocessing.cpu_count()
            return ComponentHealth(
                name="workers",
                status=ComponentStatus.UP,
                message=f"System has {worker_count} logical CPUs available",
                metadata={"logical_cpus": worker_count},
            )
        except Exception as exc:
            return ComponentHealth(
                name="workers",
                status=ComponentStatus.DEGRADED,
                message=f"Unable to determine worker capacity: {exc}",
            )

    async def check_cache() -> ComponentHealth:
        import os
        import tempfile

        try:
            cache_dir = os.path.join(tempfile.gettempdir(), "pipeline_cache")
            if os.path.isdir(cache_dir):
                items = os.listdir(cache_dir)
                return ComponentHealth(
                    name="cache",
                    status=ComponentStatus.UP,
                    message=f"Cache directory accessible with {len(items)} entries",
                    metadata={"cache_dir": cache_dir, "entries": len(items)},
                )
            os.makedirs(cache_dir, exist_ok=True)
            return ComponentHealth(
                name="cache",
                status=ComponentStatus.UP,
                message="Cache directory initialized",
                metadata={"cache_dir": cache_dir},
            )
        except Exception as exc:
            return ComponentHealth(
                name="cache",
                status=ComponentStatus.DOWN,
                message=f"Cache health check failed: {exc}",
            )

    async def check_queue() -> ComponentHealth:
        import importlib

        try:
            mod = importlib.import_module("asyncio")
            if hasattr(mod, "Queue"):
                return ComponentHealth(
                    name="queue",
                    status=ComponentStatus.UP,
                    message="Async queue subsystem available",
                    metadata={"backend": "asyncio"},
                )
            return ComponentHealth(
                name="queue",
                status=ComponentStatus.DEGRADED,
                message="Queue module loaded but missing expected interface",
            )
        except ImportError:
            return ComponentHealth(
                name="queue",
                status=ComponentStatus.DOWN,
                message="Queue subsystem unavailable: asyncio not found",
            )
        except Exception as exc:
            return ComponentHealth(
                name="queue",
                status=ComponentStatus.DOWN,
                message=f"Queue health check failed: {exc}",
            )

    async def check_api() -> ComponentHealth:
        return await _check_http_health(
            {
                "name": "api",
                "url": "http://localhost:8000/health",
            }
        )

    async def check_websocket() -> ComponentHealth:
        import importlib

        try:
            ws_mod = importlib.import_module("websockets")
            version = getattr(ws_mod, "__version__", "unknown")
            return ComponentHealth(
                name="websocket",
                status=ComponentStatus.UP,
                message=f"WebSocket server module available (v{version})",
                metadata={"version": version},
            )
        except ImportError:
            try:
                importlib.import_module("starlette.websockets")
                return ComponentHealth(
                    name="websocket",
                    status=ComponentStatus.UP,
                    message="WebSocket support available via Starlette",
                    metadata={"backend": "starlette"},
                )
            except ImportError:
                return ComponentHealth(
                    name="websocket",
                    status=ComponentStatus.DOWN,
                    message="WebSocket support unavailable",
                )
        except Exception as exc:
            return ComponentHealth(
                name="websocket",
                status=ComponentStatus.DEGRADED,
                message=f"WebSocket check encountered an issue: {exc}",
            )

    checker.register("redis", check_redis)
    checker.register("sqlite", check_sqlite)
    checker.register("workers", check_workers)
    checker.register("cache", check_cache)
    checker.register("queue", check_queue)
    checker.register("api", check_api)
    checker.register("websocket", check_websocket)

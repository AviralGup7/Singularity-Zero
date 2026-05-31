"""Health check endpoint returning service status, uptime, and dependencies health."""

import asyncio
import logging
import time
from collections.abc import Awaitable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, Field

from src.infrastructure.security.encryption import redis_tls_kwargs_from_env

logger = logging.getLogger(__name__)

_START_TIME: float = time.time()
_SQLITE_HEALTH_TIMEOUT_SECONDS = 2.0
_SQLITE_BUSY_TIMEOUT_MS = 1000


class HealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class DependencyStatus(StrEnum):
    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"


class DependencyHealth(BaseModel):
    status: DependencyStatus
    latency_ms: float | None = None
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ServiceHealth(BaseModel):
    name: str
    version: str
    status: HealthStatus
    uptime_seconds: float
    timestamp: str
    dependencies: dict[str, DependencyHealth] = Field(default_factory=dict)
    checks: dict[str, bool] = Field(default_factory=dict)


class HealthCheckResult(BaseModel):
    service: ServiceHealth
    raw_checks: dict[str, dict[str, Any]] = Field(default_factory=dict)


def _stats_value(stats: Any, key: str, default: Any = None) -> Any:
    if stats is None:
        return default
    if isinstance(stats, dict):
        return stats.get(key, default)
    return getattr(stats, key, default)


def _compute_uptime() -> float:
    return round(time.time() - _START_TIME, 1)


async def check_redis(redis_url: str | None) -> DependencyHealth:
    if not redis_url:
        return DependencyHealth(status=DependencyStatus.DOWN, details={"reason": "not configured"})
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(
            redis_url,
            socket_timeout=1.0,
            socket_connect_timeout=1.0,
            **redis_tls_kwargs_from_env(),
        )
        try:
            start = time.monotonic()
            await cast(Awaitable[Any], client.ping())
            latency = round((time.monotonic() - start) * 1000, 2)
            return DependencyHealth(status=DependencyStatus.UP, latency_ms=latency)
        finally:
            await client.close()
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)
        return DependencyHealth(status=DependencyStatus.DOWN, error=str(exc))


async def check_database(db_path: str) -> DependencyHealth:
    async def _probe() -> DependencyHealth:
        import aiosqlite

        start = time.monotonic()
        conn = await aiosqlite.connect(db_path, timeout=1.0)
        try:
            await conn.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}")
            await conn.execute("SELECT 1")
            try:
                await conn.execute("CREATE TEMP TABLE IF NOT EXISTS health_probe (ok INTEGER)")
                status = DependencyStatus.UP
                details: dict[str, Any] = {}
            except Exception as exc:
                status = DependencyStatus.DEGRADED
                details = {"mode": "read_only", "write_error": str(exc)}
        finally:
            await conn.close()
        latency = round((time.monotonic() - start) * 1000, 2)
        return DependencyHealth(status=status, latency_ms=latency, details=details)

    try:
        return await asyncio.wait_for(_probe(), timeout=_SQLITE_HEALTH_TIMEOUT_SECONDS)
    except TimeoutError:
        logger.warning(
            "Database health check timed out after %.1fs", _SQLITE_HEALTH_TIMEOUT_SECONDS
        )
        return DependencyHealth(
            status=DependencyStatus.DOWN,
            error=f"timed out after {_SQLITE_HEALTH_TIMEOUT_SECONDS:.1f}s",
        )
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return DependencyHealth(status=DependencyStatus.DOWN, error=str(exc))


async def check_services(workspace_root: Any, output_root: Any) -> DependencyHealth:
    try:
        from src.dashboard.services import DashboardServices

        services = DashboardServices(
            workspace_root=workspace_root,
            output_root=output_root,
            config_template=Path("/tmp/dummy_config.json"),  # nosec B108 # noqa: S108
        )
        start = time.monotonic()
        targets = services.list_targets()
        latency = round((time.monotonic() - start) * 1000, 2)
        return DependencyHealth(
            status=DependencyStatus.UP,
            latency_ms=latency,
            details={"targets_count": len(targets)},
        )
    except Exception as exc:
        logger.warning("Services health check failed: %s", exc)
        return DependencyHealth(status=DependencyStatus.DOWN, error=str(exc))


async def check_cache(cache_manager: Any) -> DependencyHealth:
    if cache_manager is None:
        return DependencyHealth(status=DependencyStatus.DOWN, details={"reason": "not initialised"})
    try:
        start = time.monotonic()
        stats = cache_manager.get_stats()
        latency = round((time.monotonic() - start) * 1000, 2)
        return DependencyHealth(
            status=DependencyStatus.UP,
            latency_ms=latency,
            details={
                "total_entries": int(_stats_value(stats, "total_entries", 0) or 0),
                "active_entries": int(_stats_value(stats, "active_entries", 0) or 0),
                "backend_type": str(_stats_value(stats, "backend_type", "") or ""),
            },
        )
    except Exception as exc:
        logger.warning("Cache health check failed: %s", exc)
        return DependencyHealth(status=DependencyStatus.DOWN, error=str(exc))


async def check_storage(storage_cfg: dict[str, Any] | None, output_root: Any) -> DependencyHealth:
    try:
        from src.core.storage.factory import create_artifact_store

        start = time.monotonic()
        # default to local if no storage config
        store = create_artifact_store(storage_cfg, output_root)

        # Simple test: check if we can list
        store.list("health-check-probe")

        latency = round((time.monotonic() - start) * 1000, 2)
        backend = (storage_cfg or {}).get("backend", "local")

        return DependencyHealth(
            status=DependencyStatus.UP, latency_ms=latency, details={"backend": backend}
        )
    except Exception as exc:
        logger.warning("Storage health check failed: %s", exc)
        return DependencyHealth(status=DependencyStatus.DOWN, error=str(exc))


async def run_health_checks(
    version: str = "1.0.0",
    redis_url: str | None = None,
    db_path: str | None = None,
    workspace_root: Any = None,
    output_root: Any = None,
    cache_manager: Any = None,
    storage_config: dict[str, Any] | None = None,
) -> HealthCheckResult:
    dependencies: dict[str, DependencyHealth] = {}
    checks: dict[str, bool] = {}

    if redis_url:
        redis_health = await check_redis(redis_url)
        dependencies["redis"] = redis_health
        checks["redis"] = redis_health.status == DependencyStatus.UP

    if db_path:
        db_health = await check_database(db_path)
        dependencies["database"] = db_health
        checks["database"] = db_health.status == DependencyStatus.UP

    if workspace_root and output_root:
        svc_health = await check_services(workspace_root, output_root)
        dependencies["services"] = svc_health
        checks["services"] = svc_health.status == DependencyStatus.UP

    if output_root:
        storage_health = await check_storage(storage_config, output_root)
        dependencies["storage"] = storage_health
        checks["storage"] = storage_health.status == DependencyStatus.UP

    if cache_manager is not None:
        cache_health = await check_cache(cache_manager)
        dependencies["cache"] = cache_health
        checks["cache"] = cache_health.status == DependencyStatus.UP

    all_healthy = all(checks.values()) if checks else True
    any_healthy = any(checks.values()) if checks else False

    if all_healthy:
        overall_status = HealthStatus.OK
    elif any_healthy:
        overall_status = HealthStatus.DEGRADED
    else:
        overall_status = HealthStatus.UNHEALTHY

    service = ServiceHealth(
        name="Cyber Security Test Pipeline Dashboard",
        version=version,
        status=overall_status,
        uptime_seconds=_compute_uptime(),
        timestamp=datetime.now(UTC).isoformat(),
        dependencies=dependencies,
        checks=checks,
    )

    raw_checks: dict[str, dict[str, Any]] = {}
    for name, dep in dependencies.items():
        raw_checks[name] = {
            "status": dep.status.value,
            "latency_ms": dep.latency_ms,
            "error": dep.error,
            "details": dep.details,
        }

    return HealthCheckResult(service=service, raw_checks=raw_checks)

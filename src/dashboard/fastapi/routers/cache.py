"""Cache management endpoints for the FastAPI dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sqlite3
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.dependencies import (
    check_rate_limit,
    get_cache_manager,
    get_config,
    require_admin,
    require_auth,
)
from src.dashboard.fastapi.schemas import (
    CacheCleanupResponse,
    CacheKeyDeleteRequest,
    CacheKeyDeleteResponse,
    CacheKeyInfo,
    CacheKeysResponse,
    CacheNamespaceResponse,
    CachePerformanceHistoryResponse,
    CachePerformancePoint,
    CacheStatsResponse,
    CacheStatusResponse,
    ErrorResponse,
    RedisCacheOverview,
    SQLiteCacheOverview,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cache", tags=["Cache"])
_PERFORMANCE_HISTORY: deque[dict[str, Any]] = deque(maxlen=60)


def _format_bytes(size: int | float | None) -> str:
    value = float(size or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "0 B"


def _redis_url(config: DashboardConfig) -> str | None:
    return config.redis_url or os.environ.get("REDIS_URL") or os.environ.get("CACHE_REDIS_URL")


def _get_redis_client(config: DashboardConfig) -> Any | None:
    url = _redis_url(config)
    if not url:
        return None
    try:
        import redis

        client = redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=3,
            retry_on_timeout=True,
        )
        client.ping()
        return client
    except Exception as exc:
        logger.debug("Redis introspection unavailable: %s", exc)
        return None


def _rate_pair(hits: int, misses: int) -> tuple[float | None, float | None]:
    total = hits + misses
    if total <= 0:
        return None, None
    return hits / total, misses / total


def _redis_overview(config: DashboardConfig) -> RedisCacheOverview:
    url = _redis_url(config)
    if not url:
        return RedisCacheOverview(connected=False, error="Redis URL is not configured")

    client = _get_redis_client(config)
    if client is None:
        return RedisCacheOverview(connected=False, error="Redis is not connected")

    try:
        info = client.info()
        hits = int(info.get("keyspace_hits", 0) or 0)
        misses = int(info.get("keyspace_misses", 0) or 0)
        hit_rate, miss_rate = _rate_pair(hits, misses)
        used_memory = int(info.get("used_memory", 0) or 0)
        max_memory = int(info.get("maxmemory", 0) or 0) or None
        return RedisCacheOverview(
            connected=True,
            keys_count=int(client.dbsize()),
            used_memory_human=str(info.get("used_memory_human") or _format_bytes(used_memory)),
            used_memory_bytes=used_memory,
            max_memory_bytes=max_memory,
            hit_rate=hit_rate,
            miss_rate=miss_rate,
            connected_clients=int(info.get("connected_clients", 0) or 0),
        )
    except Exception as exc:
        logger.debug("Redis status failed: %s", exc)
        return RedisCacheOverview(connected=False, error=str(exc))
    finally:
        with contextlib.suppress(Exception):
            client.close()


def _sqlite_db_path(config: DashboardConfig, cache_manager: Any | None = None) -> Path:
    l2 = getattr(cache_manager, "l2", None)
    backend_path = getattr(l2, "_db_path", None)
    return Path(backend_path or config.cache_db_path)


def _sqlite_overview(
    config: DashboardConfig,
    cache_manager: Any | None = None,
) -> SQLiteCacheOverview:
    db_path = _sqlite_db_path(config, cache_manager)
    if not db_path.exists():
        return SQLiteCacheOverview(
            connected=False,
            db_path=str(db_path),
            error="SQLite cache database does not exist",
        )

    try:
        file_size_mb = round(db_path.stat().st_size / (1024 * 1024), 3)
        entry_count = 0
        query_count = 0
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='cache_entries'"
            )
            if cursor.fetchone():
                entry_count = int(conn.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0])
                columns = {row[1] for row in conn.execute("PRAGMA table_info(cache_entries)").fetchall()}
                if "access_count" in columns:
                    raw_count = conn.execute(
                        "SELECT COALESCE(SUM(access_count), 0) FROM cache_entries"
                    ).fetchone()[0]
                    query_count = int(raw_count or 0)
                else:
                    query_count = entry_count
        finally:
            conn.close()

        hit_ratio: float | None = None
        from typing import Any, cast
        metrics: dict[str, Any] = cast(dict[str, Any], getattr(cache_manager, "get_metrics_snapshot", lambda: {})())
        hits = int(metrics.get("hits", 0) or 0)
        misses = int(metrics.get("misses", 0) or 0)
        if hits + misses > 0:
            hit_ratio = hits / (hits + misses)

        return SQLiteCacheOverview(
            connected=True,
            db_path=str(db_path),
            file_size_mb=file_size_mb,
            query_count=query_count,
            entry_count=entry_count,
            cache_hit_ratio=hit_ratio,
        )
    except Exception as exc:
        logger.debug("SQLite cache status failed: %s", exc)
        return SQLiteCacheOverview(connected=False, db_path=str(db_path), error=str(exc))


def _local_rate_pair(cache_manager: Any) -> tuple[float | None, float | None]:
    metrics = cache_manager.get_metrics_snapshot()
    hits = int(metrics.get("hits", 0) or 0)
    misses = int(metrics.get("misses", 0) or 0)
    return _rate_pair(hits, misses)


def _sample_cache_performance(config: DashboardConfig, cache_manager: Any) -> dict[str, Any]:
    redis_status = _redis_overview(config)
    local_hit_rate, local_miss_rate = _local_rate_pair(cache_manager)
    hit_rate = redis_status.hit_rate if redis_status.hit_rate is not None else local_hit_rate
    miss_rate = redis_status.miss_rate if redis_status.miss_rate is not None else local_miss_rate
    epoch = time.time()
    point = {
        "timestamp": datetime.fromtimestamp(epoch, tz=UTC).isoformat(),
        "epoch": epoch,
        "hit_rate": hit_rate,
        "miss_rate": miss_rate,
        "redis_hit_rate": redis_status.hit_rate,
        "redis_miss_rate": redis_status.miss_rate,
        "local_hit_rate": local_hit_rate,
        "local_miss_rate": local_miss_rate,
    }
    _PERFORMANCE_HISTORY.append(point)
    return point


async def cache_analytics_loop(app: Any) -> None:
    """Sample cache hit/miss rates once per minute for the rolling history API."""
    while True:
        try:
            await asyncio.to_thread(
                _sample_cache_performance,
                app.state.config,
                app.state.cache_manager,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("Cache analytics sample failed: %s", exc)
        await asyncio.sleep(60)


def start_cache_analytics(app: Any) -> asyncio.Task[None]:
    """Start the background cache analytics sampler."""
    return asyncio.create_task(cache_analytics_loop(app), name="cache-analytics")


@router.get(
    "/stats",
    response_model=CacheStatsResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get cache statistics",
)
async def get_cache_stats(
    _auth: Any = Depends(require_auth),
    cache_manager: Any = Depends(get_cache_manager),
) -> CacheStatsResponse:
    """Return cache statistics including hit/miss rates and entry counts."""
    stats = cache_manager.get_stats()
    return CacheStatsResponse(
        total_entries=stats.total_entries,
        active_entries=stats.active_entries,
        expired_entries=stats.expired_entries,
        total_size_bytes=stats.total_size_bytes,
        namespaces=stats.namespaces,
        metrics=stats.metrics.snapshot(),
        backend_type=stats.backend_type,
        l1_entries=stats.l1_entries,
        l2_entries=stats.l2_entries,
        l3_entries=stats.l3_entries,
    )


@router.get(
    "/status",
    response_model=CacheStatusResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Get cache backend status",
)
async def get_cache_status(
    _auth: Any = Depends(require_admin),
    config: DashboardConfig = Depends(get_config),
    cache_manager: Any = Depends(get_cache_manager),
) -> CacheStatusResponse:
    """Return Redis and SQLite cache status without mutating cache contents."""
    redis_status, sqlite_status = await asyncio.gather(
        asyncio.to_thread(_redis_overview, config),
        asyncio.to_thread(_sqlite_overview, config, cache_manager),
    )
    return CacheStatusResponse(redis=redis_status, sqlite=sqlite_status)


@router.get(
    "/keys",
    response_model=CacheKeysResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="List Redis keys",
)
async def list_cache_keys(
    pattern: str = Query(default="*", min_length=1, max_length=512),
    limit: int = Query(default=100, ge=1, le=1000),
    _auth: Any = Depends(require_admin),
    config: DashboardConfig = Depends(get_config),
) -> CacheKeysResponse:
    """List Redis keys matching a glob pattern with TTL and size metadata."""

    def _list() -> CacheKeysResponse:
        client = _get_redis_client(config)
        if client is None:
            return CacheKeysResponse(
                pattern=pattern,
                limit=limit,
                connected=False,
                error="Redis is not connected",
            )
        keys: list[CacheKeyInfo] = []
        truncated = False
        try:
            for raw_key in client.scan_iter(match=pattern, count=100):
                if len(keys) >= limit:
                    truncated = True
                    break
                ttl = client.ttl(raw_key)
                if ttl == -2:
                    continue
                key_type: str | None = None
                with contextlib.suppress(Exception):
                    key_type = str(client.type(raw_key))
                size: int | None = None
                with contextlib.suppress(Exception):
                    size = client.memory_usage(raw_key)
                keys.append(
                    CacheKeyInfo(
                        key=str(raw_key),
                        ttl=None if ttl == -1 else int(ttl),
                        size=size,
                        type=key_type,
                    )
                )
            return CacheKeysResponse(
                pattern=pattern,
                limit=limit,
                count=len(keys),
                truncated=truncated,
                connected=True,
                keys=keys,
            )
        except Exception as exc:
            return CacheKeysResponse(
                pattern=pattern,
                limit=limit,
                connected=False,
                error=str(exc),
            )
        finally:
            with contextlib.suppress(Exception):
                client.close()

    return await asyncio.to_thread(_list)


@router.delete(
    "/keys",
    response_model=CacheKeyDeleteResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Delete Redis keys by pattern",
)
async def delete_cache_keys(
    body: CacheKeyDeleteRequest,
    _auth: Any = Depends(require_admin),
    _rate_limit: Any = Depends(check_rate_limit),
    config: DashboardConfig = Depends(get_config),
) -> CacheKeyDeleteResponse:
    """Delete Redis keys matching a pattern using SCAN and batched DEL."""

    def _delete() -> CacheKeyDeleteResponse:
        client = _get_redis_client(config)
        if client is None:
            return CacheKeyDeleteResponse(
                pattern=body.pattern,
                connected=False,
                error="Redis is not connected",
            )
        matched = 0
        deleted = 0
        batch: list[str] = []
        try:
            for raw_key in client.scan_iter(match=body.pattern, count=250):
                matched += 1
                batch.append(raw_key)
                if len(batch) >= 500:
                    deleted += int(client.delete(*batch))
                    batch.clear()
            if batch:
                deleted += int(client.delete(*batch))
            logger.info("Redis cache pattern '%s' deleted %d/%d keys", body.pattern, deleted, matched)
            return CacheKeyDeleteResponse(
                pattern=body.pattern,
                matched=matched,
                deleted=deleted,
                connected=True,
            )
        except Exception as exc:
            return CacheKeyDeleteResponse(
                pattern=body.pattern,
                matched=matched,
                deleted=deleted,
                connected=False,
                error=str(exc),
            )
        finally:
            with contextlib.suppress(Exception):
                client.close()

    return await asyncio.to_thread(_delete)


@router.get(
    "/performance-history",
    response_model=CachePerformanceHistoryResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Get cache performance history",
)
async def get_cache_performance_history(
    _auth: Any = Depends(require_admin),
    config: DashboardConfig = Depends(get_config),
    cache_manager: Any = Depends(get_cache_manager),
) -> CachePerformanceHistoryResponse:
    """Return the last hour of one-minute cache hit/miss samples."""
    if not _PERFORMANCE_HISTORY:
        await asyncio.to_thread(_sample_cache_performance, config, cache_manager)
    return CachePerformanceHistoryResponse(
        points=[CachePerformancePoint(**point) for point in _PERFORMANCE_HISTORY]
    )


@router.post(
    "/cleanup",
    response_model=CacheCleanupResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Trigger cache cleanup",
)
async def trigger_cache_cleanup(
    _auth: Any = Depends(require_admin),
    _rate_limit: Any = Depends(check_rate_limit),
    cache_manager: Any = Depends(get_cache_manager),
) -> CacheCleanupResponse:
    """Run cache cleanup to remove expired entries."""
    start = time.monotonic()
    cleaned = cache_manager.cleanup_expired()
    duration = time.monotonic() - start
    logger.info("Cache cleanup: removed %d entries in %.2fs", cleaned, duration)
    return CacheCleanupResponse(cleaned=cleaned, duration_seconds=duration)


@router.post(
    "/clear",
    response_model=CacheNamespaceResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Clear all cache entries",
)
async def clear_all_cache(
    _auth: Any = Depends(require_admin),
    _rate_limit: Any = Depends(check_rate_limit),
    cache_manager: Any = Depends(get_cache_manager),
) -> CacheNamespaceResponse:
    """Clear all entries from the configured cache manager."""
    cleared = cache_manager.clear()
    logger.info("All cache tiers cleared: %d entries", cleared)
    return CacheNamespaceResponse(cleared=cleared, namespace="*")


@router.delete(
    "/{namespace}",
    response_model=CacheNamespaceResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Invalidate cache namespace",
)
async def invalidate_cache_namespace(
    namespace: str,
    _auth: Any = Depends(require_admin),
    _rate_limit: Any = Depends(check_rate_limit),
    cache_manager: Any = Depends(get_cache_manager),
) -> CacheNamespaceResponse:
    """Clear all entries in the specified cache namespace."""
    cleared = cache_manager.clear(namespace=namespace)
    logger.info("Cache namespace '%s' invalidated: %d entries cleared", namespace, cleared)
    return CacheNamespaceResponse(cleared=cleared, namespace=namespace)

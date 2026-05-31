"""Cache efficiency telemetry snapshots.

This module keeps cache telemetry owned by the cache subsystem while exposing
a plain-dict shape that shared API layers can consume without knowing backend
details.
"""

from __future__ import annotations

from typing import Any

from src.infrastructure.cache.models import CacheMetrics, CacheStats

CACHE_EFFICIENCY_FIELDS = (
    "hits",
    "misses",
    "total_gets",
    "hit_ratio",
    "sets",
    "deletes",
    "evictions",
    "expirations",
    "backend_errors",
    "avg_get_latency_ms",
    "avg_set_latency_ms",
)


def _coerce_metrics(raw: Any) -> CacheMetrics:
    if isinstance(raw, CacheMetrics):
        return raw
    if isinstance(raw, dict):
        values = {key: raw.get(key, 0) for key in CacheMetrics.model_fields}
        return CacheMetrics(**values)
    return CacheMetrics()


def _stats_to_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, CacheStats):
        return raw.model_dump()
    if isinstance(raw, dict):
        return dict(raw)
    return {}


def _backend_health(stats: dict[str, Any]) -> dict[str, Any]:
    backend_info = stats.get("backend_info")
    if isinstance(backend_info, dict) and backend_info:
        return backend_info

    backend = stats.get("backend") or stats.get("backend_type")
    if not backend:
        return {}

    health: dict[str, Any] = {"backend": backend}
    if "healthy" in stats:
        health["healthy"] = bool(stats["healthy"])
    if "connected" in stats:
        health["connected"] = bool(stats["connected"])
    if "error" in stats:
        health["error"] = stats["error"]
    return health


def build_cache_efficiency_snapshot(
    cache: Any | None = None,
    *,
    metrics: CacheMetrics | dict[str, Any] | None = None,
    stats: CacheStats | dict[str, Any] | None = None,
    backend_type: str | None = None,
) -> dict[str, Any]:
    """Build a cache-owned telemetry snapshot for shared callers.

    Args:
        cache: Optional cache object with ``get_metrics`` and/or stats methods.
        metrics: Optional explicit metrics source.
        stats: Optional explicit stats source.
        backend_type: Optional backend type override.

    Returns:
        Plain dict containing stable efficiency fields and available backend
        state.
    """
    raw_metrics: Any = metrics
    if raw_metrics is None and cache is not None and hasattr(cache, "get_metrics"):
        raw_metrics = cache.get_metrics()

    raw_stats: Any = stats
    if raw_stats is None and cache is not None:
        if hasattr(cache, "get_stats"):
            raw_stats = cache.get_stats()
        elif hasattr(cache, "get_cache_stats"):
            raw_stats = cache.get_cache_stats()

    metric_values = _coerce_metrics(raw_metrics)
    stat_values = _stats_to_dict(raw_stats)
    total_gets = metric_values.hits + metric_values.misses

    resolved_backend_type = backend_type or str(
        stat_values.get("backend_type") or stat_values.get("backend") or "unknown"
    )

    return {
        "subsystem": "cache",
        "backend_type": resolved_backend_type,
        "hits": metric_values.hits,
        "misses": metric_values.misses,
        "total_gets": total_gets,
        "hit_ratio": metric_values.hit_rate,
        "sets": metric_values.sets,
        "deletes": metric_values.deletes,
        "evictions": metric_values.evictions,
        "expirations": metric_values.expirations,
        "backend_errors": metric_values.errors,
        "total_get_latency_ms": metric_values.total_get_time_ms,
        "avg_get_latency_ms": metric_values.avg_get_time_ms,
        "total_set_latency_ms": metric_values.total_set_time_ms,
        "avg_set_latency_ms": metric_values.avg_set_time_ms,
        "total_entries": int(stat_values.get("total_entries", 0) or 0),
        "active_entries": int(stat_values.get("active_entries", 0) or 0),
        "expired_entries": int(stat_values.get("expired_entries", 0) or 0),
        "backend_health": _backend_health(stat_values),
    }

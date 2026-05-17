"""Bloom mesh health and reconciliation endpoints."""

from __future__ import annotations

import time
from typing import Any, cast

from fastapi import APIRouter, Depends, Request

from src.core.frontier.bloom import NeuralBloomFilter
from src.dashboard.fastapi.dependencies import require_admin

router = APIRouter(prefix="/api/bloom", tags=["Bloom"])


@router.get("/health")
async def bloom_health(request: Request) -> dict[str, Any]:
    """Return Bloom filter mesh health for dashboard tiles."""
    bloom_mesh = getattr(request.app.state, "bloom_mesh", None)
    if bloom_mesh is not None:
        return cast(dict[str, Any], bloom_mesh.health_snapshot())

    fallback = NeuralBloomFilter()
    stats = fallback.get_stats()
    return {
        "nodes": [
            {
                "node_id": "local",
                "memory_mb": stats["memory_mb"],
                "element_count": stats["element_count"],
                "false_positive_probability": stats["false_positive_probability"],
                "fill_ratio": stats["fill_ratio"],
                "last_sync_time": 0.0,
                "capacity": stats["capacity"],
                "hash_count": stats["hash_count"],
                "clock": {},
                "stale": False,
            }
        ],
        "saturation_history": [
            {"time": time.time(), "fill_ratio": 0.0, "false_positive_probability": 0.0}
        ],
        "sync_interval_seconds": 0.0,
        "redis_enabled": False,
        "channel": "",
    }


@router.post("/reconcile", dependencies=[Depends(require_admin)])
async def reconcile_bloom_mesh(request: Request) -> dict[str, Any]:
    """Force an immediate Bloom snapshot publish across online nodes."""
    bloom_mesh = getattr(request.app.state, "bloom_mesh", None)
    if bloom_mesh is None:
        return {"status": "unavailable", "redis_enabled": False}
    return cast(dict[str, Any], await bloom_mesh.force_reconcile())

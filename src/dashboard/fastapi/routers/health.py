"""Health check endpoints for the FastAPI dashboard."""

import logging
import time
from datetime import UTC
from typing import Any
from dataclasses import asdict

from fastapi import APIRouter, Depends, Request

from src.dashboard.fastapi.dependencies import get_cache_manager, get_config
from src.dashboard.fastapi.schemas import HealthResponse, ReadinessResponse, MeshNodeSchema

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/health", tags=["Health"])

_START_TIME: float = time.time()


@router.get(
    "",
    response_model=HealthResponse,
    summary="Health check",
)
async def health_check(
    request: Request,
    config: Any = Depends(get_config),
    cache_manager: Any = Depends(get_cache_manager),
) -> HealthResponse:
    """Comprehensive health check endpoint with distributed mesh telemetry."""
    from src.dashboard.health import run_health_checks

    result = await run_health_checks(
        version="2.0.0",
        redis_url=config.redis_url,
        db_path=config.cache_db_path,
        workspace_root=config.workspace_root,
        output_root=config.output_root,
        cache_manager=cache_manager,
        storage_config=config.storage_config,
    )

    # --- Frontier Overhaul: Mesh Telemetry ---
    mesh_nodes: list[MeshNodeSchema] = []
    gossip = getattr(request.app.state, "gossip", None)
    if gossip:
        # 1. Local Node
        local_data = asdict(gossip.local_node)
        mesh_nodes.append(MeshNodeSchema(**local_data))
        # 2. Remote Peers
        for peer in gossip.peers.values():
            mesh_nodes.append(MeshNodeSchema(**asdict(peer)))

    return HealthResponse(
        status=result.service.status.value,
        timestamp=result.service.timestamp,
        version=result.service.version,
        uptime_seconds=result.service.uptime_seconds,
        dependencies=result.raw_checks,
        mesh=mesh_nodes
    )


@router.get(
    "/mesh",
    summary="Mesh health",
)
async def mesh_health(request: Request) -> dict[str, Any]:
    """Return detailed local view of mesh membership and transport health."""
    gossip = getattr(request.app.state, "gossip", None)
    if not gossip:
        return {
            "peer_count": 0,
            "leader_id": "",
            "avg_latency_ms": 0.0,
            "drop_rate": 0.0,
            "active_heartbeats": False,
            "nodes": [],
            "edges": [],
        }
    return gossip.mesh_health()


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check",
)
async def readiness_check(
    config: Any = Depends(get_config),
    cache_manager: Any = Depends(get_cache_manager),
) -> ReadinessResponse:
    """Readiness check. Returns ready=true if all critical dependencies are UP."""
    from src.dashboard.health import run_health_checks

    result = await run_health_checks(
        version="2.0.0",
        redis_url=config.redis_url,
        db_path=config.cache_db_path,
        workspace_root=config.workspace_root,
        output_root=config.output_root,
        cache_manager=cache_manager,
        storage_config=config.storage_config,
    )

    return ReadinessResponse(
        ready=result.service.status == "ok",
        checks=result.service.checks,
    )


@router.get(
    "/live",
    response_model=HealthResponse,
    summary="Liveness check",
)
async def liveness_check() -> HealthResponse:
    """Liveness check. Returns OK if the process is alive."""
    from datetime import datetime

    return HealthResponse(
        status="ok",
        timestamp=datetime.now(UTC).isoformat(),
    )

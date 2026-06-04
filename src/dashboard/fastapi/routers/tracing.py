"""Tracing configuration and local span explorer endpoints."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query

from src.core.frontier.tracing_manager import get_tracing_manager
from src.dashboard.fastapi.dependencies import require_auth

router = APIRouter(prefix="/api", tags=["Tracing"])


@router.get(
    "/tracing/config",
    responses={401: {"description": "Unauthorized"}},
    summary="Return OTLP exporter configuration (authenticated)",
)
async def tracing_config(_auth: Any = Depends(require_auth)) -> dict[str, Any]:
    """Return OTLP exporter configuration and reachability.

    SECURITY: requires authentication. The configuration includes the
    OTLP endpoint URL and the service name, both of which leak
    internal architecture if exposed unauthenticated.
    """
    return cast(dict[str, Any], get_tracing_manager().get_config())


@router.get(
    "/traces",
    responses={401: {"description": "Unauthorized"}},
    summary="List recent traces (authenticated)",
)
async def list_traces(
    service_name: str | None = Query(default=None),
    start_ms: int | None = Query(default=None),
    end_ms: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """List recent traces from the local SQLite span store."""
    traces = get_tracing_manager().list_traces(
        service_name=service_name,
        start_ms=start_ms,
        end_ms=end_ms,
        limit=limit,
    )
    return {"traces": traces}


@router.get(
    "/traces/{trace_id}",
    responses={401: {"description": "Unauthorized"}, 404: {"description": "Not found"}},
    summary="Return all spans for a trace (authenticated)",
)
async def get_trace(
    trace_id: str,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return all spans for a trace in waterfall order."""
    trace = get_tracing_manager().get_trace(trace_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return trace

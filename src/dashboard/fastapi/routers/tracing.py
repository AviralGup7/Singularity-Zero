"""Tracing configuration and local span explorer endpoints."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query

from src.core.frontier.tracing_manager import get_tracing_manager

router = APIRouter(prefix="/api", tags=["Tracing"])


@router.get("/tracing/config")
async def tracing_config() -> dict[str, Any]:
    """Return OTLP exporter configuration and reachability."""
    return cast(dict[str, Any], get_tracing_manager().get_config())


@router.get("/traces")
async def list_traces(
    service_name: str | None = Query(default=None),
    start_ms: int | None = Query(default=None),
    end_ms: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """List recent traces from the local SQLite span store."""
    traces = get_tracing_manager().list_traces(
        service_name=service_name,
        start_ms=start_ms,
        end_ms=end_ms,
        limit=limit,
    )
    return {"traces": traces}


@router.get("/traces/{trace_id}")
async def get_trace(trace_id: str) -> dict[str, Any]:
    """Return all spans for a trace in waterfall order."""
    trace = get_tracing_manager().get_trace(trace_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return trace

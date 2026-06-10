"""FastAPI router exposing stage trace forensics from TraceStore."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel

from src.dashboard.fastapi.dependencies import require_auth
from src.infrastructure.observability.trace_store import get_trace_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/forensics/trace", tags=["Forensics Trace"])


class TraceResponse(BaseModel):
    trace_id: str
    run_id: str
    stage_name: str
    started_at: str
    finished_at: str | None
    duration_ms: float | None
    stage_input_hash: str
    tool_invocation: dict[str, Any]
    tool_stdout: str | None
    tool_stderr: str | None
    exit_code: int | None
    state_delta_keys: list[str]
    state_pre_count: int
    state_post_count: int
    findings_produced: list[str]
    finding_event_ids: list[str]
    error: str | None
    retry_count: int


def _serialize_trace(trace: Any) -> dict[str, Any]:
    return {
        "trace_id": trace.trace_id,
        "run_id": trace.run_id,
        "stage_name": trace.stage_name,
        "started_at": trace.started_at.isoformat() if trace.started_at else None,
        "finished_at": trace.finished_at.isoformat() if trace.finished_at else None,
        "duration_ms": trace.duration_ms,
        "stage_input_hash": trace.stage_input_hash,
        "tool_invocation": trace.tool_invocation,
        "tool_stdout": trace.tool_stdout,
        "tool_stderr": trace.tool_stderr,
        "exit_code": trace.exit_code,
        "state_delta_keys": trace.state_delta_keys,
        "state_pre_count": trace.state_pre_count,
        "state_post_count": trace.state_post_count,
        "findings_produced": trace.findings_produced,
        "finding_event_ids": trace.finding_event_ids,
        "error": trace.error,
        "retry_count": trace.retry_count,
    }


@router.get(
    "/{run_id}/{stage_name}",
    responses={404: {"description": "Trace not found"}, 401: {"description": "Unauthorized"}},
    summary="Get the full StageTrace for a run+stage combination",
)
async def get_stage_trace(
    run_id: str = Path(..., min_length=1, description="Pipeline run ID"),
    stage_name: str = Path(..., min_length=1, description="Stage name"),
    trace_dir: str | None = Query(default=None, description="Override trace directory"),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    trace_store = get_trace_store(trace_dir=trace_dir or ".ai/traces")
    trace = trace_store.get_trace_for_stage(run_id, stage_name)
    if trace is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return _serialize_trace(trace)


@router.get(
    "/{run_id}",
    responses={404: {"description": "Run not found"}, 401: {"description": "Unauthorized"}},
    summary="List all StageTraces for a run",
)
async def list_run_traces(
    run_id: str = Path(..., min_length=1, description="Pipeline run ID"),
    trace_dir: str | None = Query(default=None, description="Override trace directory"),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    trace_store = get_trace_store(trace_dir=trace_dir or ".ai/traces")
    traces = trace_store.get_traces_for_run(run_id)
    return {
        "run_id": run_id,
        "trace_count": len(traces),
        "traces": [_serialize_trace(t) for t in traces],
    }


@router.get(
    "/{run_id}/{stage_name}/causal-chain/{finding_id}",
    responses={
        404: {"description": "Finding or trace not found"},
        401: {"description": "Unauthorized"},
    },
    summary="Get all stages that contributed to a specific finding",
)
async def get_finding_causal_chain(
    run_id: str = Path(..., min_length=1, description="Pipeline run ID"),
    stage_name: str = Path(..., min_length=1, description="Stage name"),
    finding_id: str = Path(..., min_length=1, description="Finding identifier"),
    trace_dir: str | None = Query(default=None, description="Override trace directory"),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    trace_store = get_trace_store(trace_dir=trace_dir or ".ai/traces")
    chain = trace_store.get_finding_causal_chain(finding_id, run_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Causal chain not found")
    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "stage_count": len(chain),
        "traces": [_serialize_trace(t) for t in chain],
    }

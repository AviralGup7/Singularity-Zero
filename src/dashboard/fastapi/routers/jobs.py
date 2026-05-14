"""Job management endpoints for the FastAPI dashboard."""

import asyncio
import json
import logging
import os
import time
from collections.abc import AsyncGenerator
from typing import Any, cast
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from src.dashboard.eta_engine import get_eta_engine
from src.dashboard.fastapi.config import FeatureFlags
from src.dashboard.fastapi.dependencies import (
    check_rate_limit,
    get_queue_client,
    require_auth,
    require_worker,
)
from src.dashboard.fastapi.routers.sse_events import SSEEventEmitter
from src.dashboard.fastapi.schemas import (
    ErrorResponse,
    JobCreateRequest,
    JobListResponse,
    JobLogsResponse,
    JobResponse,
)

logger = logging.getLogger(__name__)

# Job stall detection threshold in seconds
STALLED_THRESHOLD_SECONDS = 75

router = APIRouter(prefix="/api/jobs")


def _snapshot_job(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a stable snapshot of a job for API responses.

    Avoids re-snapshotting payloads that already contain live timing
    fields (started_at_label, elapsed_seconds, stage_progress),
    which prevents false "stalled" states from stale computed values.

    Args:
        raw: Raw job dictionary from the job store.

    Returns:
        Snapshot dict safe for API serialization.
    """
    if (
        isinstance(raw, dict)
        and "started_at_label" in raw
        and "elapsed_seconds" in raw
        and "stage_progress" in raw
    ):
        return raw

    from src.dashboard.job_state import snapshot_job

    return snapshot_job(raw)


def _current_stage_entry(job: dict[str, Any]) -> dict[str, Any] | None:
    stage_name = str(job.get("stage", "")).strip()
    stage_progress = job.get("stage_progress")
    if isinstance(stage_progress, dict) and stage_name:
        entry = stage_progress.get(stage_name)
        if isinstance(entry, dict):
            return entry
    if isinstance(stage_progress, list) and stage_name:
        for entry in stage_progress:
            if isinstance(entry, dict) and str(entry.get("stage", "")).strip() == stage_name:
                return entry
    return None


def _current_stage_percent(job: dict[str, Any], stage_entry: dict[str, Any] | None) -> int:
    if isinstance(stage_entry, dict):
        from_entry = stage_entry.get("percent")
        if isinstance(from_entry, (int, float)):
            return max(0, min(100, int(from_entry)))
    processed = job.get("stage_processed")
    total = job.get("stage_total")
    if isinstance(processed, (int, float)) and isinstance(total, (int, float)) and total > 0:
        return max(0, min(100, int((processed / total) * 100)))
    return 0


def _heartbeat_interval_seconds() -> float:
    """Resolve heartbeat interval defensively from feature flags.

    Supports both callable and scalar style values so runtime patching
    cannot crash SSE loops with type errors.
    """
    raw_value = getattr(FeatureFlags, "SSE_HEARTBEAT_INTERVAL_SECONDS", 25)
    interval = raw_value() if callable(raw_value) else raw_value
    try:
        parsed = float(interval)
    except (TypeError, ValueError):
        parsed = 25.0
    return max(5.0, parsed)


async def _get_enriched_job(job_id: str, services: Any) -> dict[str, Any]:
    job = services.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return cast(dict[str, Any], job)


@router.get(
    "",
    response_model=JobListResponse,
    responses={401: {"model": ErrorResponse}},
    summary="List all jobs",
)
async def list_jobs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: str | None = Query(None, description="Filter by status"),
    sort_by: str = Query("started_at", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> JobListResponse:
    from src.dashboard.job_state import _coerce_epoch

    all_jobs = services.list_jobs()

    if status:
        all_jobs = [j for j in all_jobs if j.get("status") == status]

    reverse = sort_order == "desc"

    def _sort_key(job: dict[str, Any]) -> float | str:
        value = job.get(sort_by)
        if sort_by in {"started_at", "finished_at", "updated_at"}:
            return _coerce_epoch(value, 0.0)
        if isinstance(value, (int, float)):
            return float(value)
        return str(value or "")

    all_jobs.sort(key=_sort_key, reverse=reverse)

    total = len(all_jobs)
    start = (page - 1) * page_size
    end = start + page_size
    page_jobs = all_jobs[start:end]

    return JobListResponse(
        jobs=[JobResponse(**_snapshot_job(j)) for j in page_jobs],
        total=total,
    )


@router.get(
    "/historical-durations",
    responses={501: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get historical stage durations",
    description="Return historical duration statistics for each pipeline stage based on past job runs. Requires ENABLE_DURATION_FORECAST=true.",
)
async def get_historical_durations(
    _auth: Any = Depends(require_auth),
) -> Any:
    if not FeatureFlags.ENABLE_DURATION_FORECAST():
        raise HTTPException(
            status_code=501,
            detail="Duration forecast is disabled. Set ENABLE_DURATION_FORECAST=true",
        )

    eta_engine = get_eta_engine()
    data = await eta_engine.get_historical_durations()
    return data


@router.get(
    "/{job_id}",
    response_model=JobResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get job details",
)
async def get_job(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> JobResponse:
    job = await _get_enriched_job(job_id, services)
    return JobResponse(**_snapshot_job(job))


def _build_jaeger_url(job_id: str, job: dict[str, Any]) -> dict[str, str]:
    base_url = os.getenv("CYBER_JAEGER_URL", "http://localhost:16686").rstrip("/")
    service_name = os.getenv("CYBER_OTEL_SERVICE_NAME", "cyber-pipeline")
    telemetry = job.get("progress_telemetry")
    trace_id = str(
        job.get("trace_id")
        or job.get("otel_trace_id")
        or (telemetry.get("trace_id") if isinstance(telemetry, dict) else "")
        or ""
    ).strip()

    if trace_id:
        return {
            "job_id": job_id,
            "trace_id": trace_id,
            "trace_url": f"{base_url}/trace/{quote(trace_id)}",
            "mode": "trace",
        }

    tags = quote(json.dumps({"job.id": job_id}, separators=(",", ":")))
    query = urlencode({"service": service_name})
    return {
        "job_id": job_id,
        "trace_id": "",
        "trace_url": f"{base_url}/search?{query}&tags={tags}",
        "mode": "search",
    }


@router.get(
    "/{job_id}/trace",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get the Jaeger deep link for a job trace",
)
async def get_job_trace_link(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, str]:
    job = await _get_enriched_job(job_id, services)
    return _build_jaeger_url(job_id, job)


@router.get(
    "/{job_id}/remediation",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get fix-command suggestions for a failed job",
)
async def get_job_remediation(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    from src.dashboard.remediation import suggest_for_job

    job = await _get_enriched_job(job_id, services)
    return {"job_id": job_id, "suggestions": suggest_for_job(job)}


@router.get(
    "/{job_id}/logs",
    response_model=JobLogsResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get job logs",
)
async def get_job_logs(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> JobLogsResponse:
    job = await _get_enriched_job(job_id, services)
    return JobLogsResponse(
        job_id=job_id,
        logs=job.get("latest_logs", []),
        total_logs=len(job.get("latest_logs", [])),
        status=job.get("status"),
    )


@router.get(
    "/{job_id}/logs/stream",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Stream job logs (SSE)",
)
async def stream_job_logs(
    job_id: str,
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> StreamingResponse:
    job = await _get_enriched_job(job_id, services)
    last_count = len(job.get("latest_logs", []))

    if FeatureFlags.ENABLE_SSE_PROGRESS():
        from src.dashboard.registry import STAGE_LABELS

        emitter = SSEEventEmitter(job_id)
        request.headers.get("last-event-id", "")
        last_stage = job.get("stage", "")

        async def typed_event_stream() -> AsyncGenerator[str]:
            nonlocal last_count, last_stage
            from src.dashboard.job_state import _coerce_epoch

            last_heartbeat = time.time()

            while True:
                if await request.is_disconnected():
                    break

                current_job = services.get_job(job_id)
                if not current_job:
                    yield emitter.error(
                        "Job not found", stage=last_stage, progress_percent=0, recoverable=False
                    )
                    break

                status = current_job.get("status", "")
                stage = current_job.get("stage", "")
                stage_label = STAGE_LABELS.get(stage, stage.replace("_", " ").title())
                progress = int(current_job.get("progress_percent", 0) or 0)

                if stage != last_stage:
                    yield emitter.stage_change(
                        previous_stage=last_stage,
                        new_stage=stage,
                        stage_label=stage_label,
                        progress_percent=progress,
                    )
                    last_stage = stage

                logs = current_job.get("latest_logs", [])
                if len(logs) > last_count:
                    new_logs = logs[last_count:]
                    last_count = len(logs)
                    for log_line in new_logs:
                        yield emitter.log(log_line)

                job_snapshot = _snapshot_job(current_job)
                stage_entry = _current_stage_entry(job_snapshot)
                processed = current_job.get("stage_processed")
                total = current_job.get("stage_total")
                state_version = int(current_job.get("state_version", 0) or 0)
                yield emitter.progress_update(
                    stage=stage,
                    stage_label=stage_label,
                    progress_percent=progress,
                    message=current_job.get("status_message", ""),
                    stage_processed=processed,
                    stage_total=total,
                    stage_percent=_current_stage_percent(job_snapshot, stage_entry),
                    status=current_job.get("status"),
                    failed_stage=current_job.get("failed_stage") or None,
                    failure_reason_code=current_job.get("failure_reason_code") or None,
                    failure_step=current_job.get("failure_step") or None,
                    failure_reason=current_job.get("failure_reason") or None,
                    stage_status=(stage_entry or {}).get("status")
                    if isinstance(stage_entry, dict)
                    else None,
                    stage_reason=(stage_entry or {}).get("reason")
                    if isinstance(stage_entry, dict)
                    else None,
                    stage_error=(stage_entry or {}).get("error")
                    if isinstance(stage_entry, dict)
                    else None,
                    retry_count=(stage_entry or {}).get("retry_count")
                    if isinstance(stage_entry, dict)
                    else None,
                    stage_progress=job_snapshot.get("stage_progress")
                    if isinstance(job_snapshot.get("stage_progress"), list)
                    else None,
                    progress_telemetry=job_snapshot.get("progress_telemetry")
                    if isinstance(job_snapshot.get("progress_telemetry"), dict)
                    else None,
                    state_version=state_version,
                )

                if status in ("completed", "failed", "stopped"):
                    # Emit error event before completed if the job failed
                    if status == "failed":
                        error_msg = current_job.get("error", "") or current_job.get(
                            "status_message", "Unknown error"
                        )
                        yield emitter.error(
                            error=str(error_msg),
                            stage=stage,
                            progress_percent=progress,
                            recoverable=False,
                            failed_stage=current_job.get("failed_stage") or stage,
                            failure_reason_code=current_job.get("failure_reason_code") or None,
                            failure_step=current_job.get("failure_step") or None,
                            failure_reason=current_job.get("failure_reason") or str(error_msg),
                            stage_progress=job_snapshot.get("stage_progress")
                            if isinstance(job_snapshot.get("stage_progress"), list)
                            else None,
                            progress_telemetry=job_snapshot.get("progress_telemetry")
                            if isinstance(job_snapshot.get("progress_telemetry"), dict)
                            else None,
                        )
                    started_at = _coerce_epoch(current_job.get("started_at"), 0.0)
                    finished_or_now = _coerce_epoch(current_job.get("finished_at"), time.time())
                    elapsed = max(0.0, finished_or_now - started_at)
                    yield emitter.completed(
                        status=status,
                        progress_percent=100 if status == "completed" else progress,
                        stage=stage,
                        stage_label=stage_label,
                        total_duration_seconds=round(elapsed, 1),
                        total_findings=current_job.get("total_findings", 0),
                        failed_stage=current_job.get("failed_stage") or None,
                        failure_reason_code=current_job.get("failure_reason_code") or None,
                        failure_step=current_job.get("failure_step") or None,
                        failure_reason=current_job.get("failure_reason") or None,
                        stage_progress=job_snapshot.get("stage_progress")
                        if isinstance(job_snapshot.get("stage_progress"), list)
                        else None,
                        progress_telemetry=job_snapshot.get("progress_telemetry")
                        if isinstance(job_snapshot.get("progress_telemetry"), dict)
                        else None,
                    )
                    break

                now = time.time()
                if now - last_heartbeat >= _heartbeat_interval_seconds():
                    updated_at = _coerce_epoch(current_job.get("updated_at"), now)
                    since_update = max(0.0, now - updated_at)
                    stalled = status == "running" and since_update >= STALLED_THRESHOLD_SECONDS
                    yield emitter.heartbeat(
                        progress_percent=progress,
                        stage=stage,
                        stage_label=stage_label,
                        stalled=stalled,
                        seconds_since_last_update=since_update,
                    )
                    last_heartbeat = now

                await asyncio.sleep(1.0)

        return StreamingResponse(
            typed_event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
    else:

        async def event_stream():
            nonlocal last_count
            while True:
                if await request.is_disconnected():
                    break

                current_job = services.get_job(job_id)
                if not current_job:
                    yield f"event: error\ndata: {json.dumps({'error': 'Job not found'})}\n\n"
                    break

                logs = current_job.get("latest_logs", [])
                if len(logs) > last_count:
                    new_logs = logs[last_count:]
                    last_count = len(logs)
                    for log_line in new_logs:
                        yield f"event: log\ndata: {json.dumps({'line': log_line})}\n\n"

                if current_job.get("status") in ("completed", "failed", "stopped"):
                    yield f"event: done\ndata: {json.dumps({'status': current_job['status']})}\n\n"
                    break

                await asyncio.sleep(1.0)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )


@router.get(
    "/{job_id}/progress/stream",
    responses={
        404: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        501: {"model": ErrorResponse},
    },
    summary="Stream job progress events (SSE)",
)
async def stream_job_progress(
    job_id: str,
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> StreamingResponse:
    if not FeatureFlags.ENABLE_SSE_PROGRESS():
        raise HTTPException(
            status_code=501,
            detail="SSE progress streaming is disabled. Set ENABLE_SSE_PROGRESS=true",
        )

    job = await _get_enriched_job(job_id, services)
    from src.dashboard.registry import STAGE_LABELS

    emitter = SSEEventEmitter(job_id)
    request.headers.get("last-event-id", "")
    last_stage = job.get("stage", "")
    last_iteration = job.get("iteration", 0)

    async def progress_event_stream() -> AsyncGenerator[str]:
        nonlocal last_stage, last_iteration
        last_heartbeat = time.time()
        last_mesh_health = 0.0

        while True:
            if await request.is_disconnected():
                break

            current_job = services.get_job(job_id)
            if not current_job:
                yield emitter.error(
                    "Job not found", stage=last_stage, progress_percent=0, recoverable=False
                )
                break

            status = current_job.get("status", "")
            stage = current_job.get("stage", "")
            stage_label = STAGE_LABELS.get(stage, stage.replace("_", " ").title())
            progress = int(current_job.get("progress_percent", 0) or 0)
            job_snapshot = _snapshot_job(current_job)

            if stage != last_stage:
                yield emitter.stage_change(
                    previous_stage=last_stage,
                    new_stage=stage,
                    stage_label=stage_label,
                    progress_percent=progress,
                )
                last_stage = stage

            processed = current_job.get("stage_processed")
            total = current_job.get("stage_total")
            stage_entry = _current_stage_entry(job_snapshot)
            yield emitter.progress_update(
                stage=stage,
                stage_label=stage_label,
                progress_percent=progress,
                message=current_job.get("status_message", ""),
                stage_processed=processed,
                stage_total=total,
                stage_percent=_current_stage_percent(job_snapshot, stage_entry),
                status=current_job.get("status"),
                failed_stage=current_job.get("failed_stage") or None,
                failure_reason_code=current_job.get("failure_reason_code") or None,
                failure_step=current_job.get("failure_step") or None,
                failure_reason=current_job.get("failure_reason") or None,
                stage_status=(stage_entry or {}).get("status")
                if isinstance(stage_entry, dict)
                else None,
                stage_reason=(stage_entry or {}).get("reason")
                if isinstance(stage_entry, dict)
                else None,
                stage_error=(stage_entry or {}).get("error")
                if isinstance(stage_entry, dict)
                else None,
                retry_count=(stage_entry or {}).get("retry_count")
                if isinstance(stage_entry, dict)
                else None,
                stage_progress=job_snapshot.get("stage_progress")
                if isinstance(job_snapshot.get("stage_progress"), list)
                else None,
                progress_telemetry=job_snapshot.get("progress_telemetry")
                if isinstance(job_snapshot.get("progress_telemetry"), dict)
                else None,
            )

            current_iteration = current_job.get("iteration", 0)
            if current_iteration != last_iteration:
                max_iterations = current_job.get("max_iterations", 0)
                stage_percent = _current_stage_percent(job_snapshot, stage_entry)
                yield emitter.iteration_change(
                    current_iteration=current_iteration,
                    max_iterations=max_iterations,
                    stage=stage,
                    stage_percent=stage_percent,
                    progress_percent=progress,
                )
                last_iteration = current_iteration

            now = time.time()
            if status == "running" and now - last_mesh_health >= 5.0:
                gossip = getattr(request.app.state, "gossip", None)
                if gossip:
                    yield emitter.mesh_health_update(gossip.mesh_health())
                last_mesh_health = now

            if status in ("completed", "failed", "stopped"):
                # Emit error event before completed if the job failed
                if status == "failed":
                    error_msg = current_job.get("error", "") or current_job.get(
                        "status_message", "Unknown error"
                    )
                    yield emitter.error(
                        error=str(error_msg),
                        stage=stage,
                        progress_percent=progress,
                        recoverable=False,
                        failed_stage=current_job.get("failed_stage") or stage,
                        failure_reason_code=current_job.get("failure_reason_code") or None,
                        failure_step=current_job.get("failure_step") or None,
                        failure_reason=current_job.get("failure_reason") or str(error_msg),
                        stage_progress=job_snapshot.get("stage_progress")
                        if isinstance(job_snapshot.get("stage_progress"), list)
                        else None,
                        progress_telemetry=job_snapshot.get("progress_telemetry")
                        if isinstance(job_snapshot.get("progress_telemetry"), dict)
                        else None,
                    )
                from src.dashboard.job_state import _coerce_epoch

                started_at = _coerce_epoch(current_job.get("started_at"), 0)
                finished_at = current_job.get("finished_at")
                now = time.time()
                finished_or_now = _coerce_epoch(finished_at, now)
                elapsed = finished_or_now - started_at
                yield emitter.completed(
                    status=status,
                    progress_percent=100 if status == "completed" else progress,
                    stage=stage,
                    stage_label=stage_label,
                    total_duration_seconds=round(elapsed, 1),
                    total_findings=current_job.get("total_findings", 0),
                    failed_stage=current_job.get("failed_stage") or None,
                    failure_reason_code=current_job.get("failure_reason_code") or None,
                    failure_step=current_job.get("failure_step") or None,
                    failure_reason=current_job.get("failure_reason") or None,
                    stage_progress=job_snapshot.get("stage_progress")
                    if isinstance(job_snapshot.get("stage_progress"), list)
                    else None,
                    progress_telemetry=job_snapshot.get("progress_telemetry")
                    if isinstance(job_snapshot.get("progress_telemetry"), dict)
                    else None,
                )
                break

            if now - last_heartbeat >= _heartbeat_interval_seconds():
                from src.dashboard.job_state import _coerce_epoch

                updated_at = _coerce_epoch(current_job.get("updated_at"), now)
                since_update = now - updated_at
                stalled = status == "running" and since_update >= STALLED_THRESHOLD_SECONDS
                yield emitter.heartbeat(
                    progress_percent=progress,
                    stage=stage,
                    stage_label=stage_label,
                    stalled=stalled,
                    seconds_since_last_update=since_update,
                )
                last_heartbeat = now

            await asyncio.sleep(1.0)

    return StreamingResponse(
        progress_event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "",
    response_model=JobResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Start a new scan job",
)
@router.post(
    "/start",
    response_model=JobResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Start a new scan job",
)
async def start_job(
    request: JobCreateRequest,
    _auth: Any = Depends(require_worker),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> JobResponse:
    """Start a new pipeline scan job.

    Creates a job record, writes config/scope files, and launches
    the pipeline subprocess in a background thread.
    """
    try:
        result = services.start(
            request.base_url,
            scope_text=request.scope_text,
            selected_modules=request.modules,
            mode_name=request.mode,
            runtime_overrides=request.runtime_overrides or None,
            execution_options=request.execution_options or None,
        )
        return JobResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to start job: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to start job")


@router.post(
    "/{job_id}/stop",
    response_model=JobResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Stop a running job",
)
async def stop_job(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> JobResponse:
    """Request graceful stop of a running pipeline job."""
    try:
        result = services.stop_job(job_id)
        return JobResponse(**_snapshot_job(result))
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    except Exception as exc:
        logger.exception("Failed to stop job %s: %s", job_id, exc)
        raise HTTPException(status_code=500, detail="Failed to stop job")


@router.post(
    "/{job_id}/restart-safe",
    response_model=JobResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Restart a job with safe defaults",
)
async def restart_job_safe(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> JobResponse:
    """Restart a previously completed or failed job with safe defaults.

    Stops the job if running, then re-launches with skip_crtsh=True
    and refresh_cache=False to avoid redundant work.
    """
    try:
        result = services.restart_job_safe(job_id)
        return JobResponse(**_snapshot_job(result))
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    except Exception as exc:
        logger.exception("Failed to restart job %s: %s", job_id, exc)
        raise HTTPException(status_code=500, detail="Failed to restart job")


@router.get(
    "/{job_id}/timeline",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get job execution timeline",
)
async def get_job_timeline(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Return execution timeline for a job showing stage transitions."""
    job = services.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    events: list[dict[str, Any]] = []

    if job.get("started_at"):
        events.append(
            {
                "event": "job_started",
                "timestamp": job["started_at"],
                "stage": "startup",
            }
        )
    if job.get("stage"):
        events.append(
            {
                "event": "stage_change",
                "timestamp": job.get("updated_at", job.get("started_at")),
                "stage": job["stage"],
                "progress": job.get("progress", 0),
            }
        )
    if job.get("status") in ("completed", "failed", "stopped"):
        events.append(
            {
                "event": f"job_{job['status']}",
                "timestamp": job.get("finished_at"),
                "stage": job.get("stage", "unknown"),
            }
        )

    return {
        "job_id": job_id,
        "target": job.get("target_name", ""),
        "status": job.get("status"),
        "events": events,
        "total_events": len(events),
    }

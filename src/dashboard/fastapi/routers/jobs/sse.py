"""Endpoints for streaming job logs and progress events via SSE."""

import asyncio
import json
import logging
import time
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from src.dashboard.feature_flags import FeatureFlags
from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.sse_events import SSEEventEmitter
from src.dashboard.fastapi.routers.utils import (
    current_stage_entry,
    current_stage_percent,
    get_enriched_job,
    heartbeat_interval_seconds,
    snapshot_job_api,
)
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

# Job stall detection threshold in seconds
STALLED_THRESHOLD_SECONDS = FeatureFlags.STALLED_THRESHOLD_SECONDS()

router = APIRouter(prefix="/api/jobs")


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
    """Stream process logs in real-time, optionally enriched with progress metadata."""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    job = await get_enriched_job(job_id, services)
    job_target = str(job.get("target_name") or job.get("hostname") or job.get("target") or "")
    if not is_target_owned_by_tenant(job_target, tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

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
            last_telemetry_count = 0

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

                job_snapshot = snapshot_job_api(current_job)
                telemetry_events = job_snapshot.get("telemetry_events")
                if (
                    isinstance(telemetry_events, list)
                    and len(telemetry_events) > last_telemetry_count
                ):
                    for telemetry in telemetry_events[last_telemetry_count:]:
                        if isinstance(telemetry, dict):
                            yield emitter.telemetry_event(telemetry)
                    last_telemetry_count = len(telemetry_events)
                stage_entry = current_stage_entry(job_snapshot)
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
                    stage_percent=current_stage_percent(job_snapshot, stage_entry),
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
                    telemetry_events=telemetry_events[-25:]
                    if isinstance(telemetry_events, list)
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
                if now - last_heartbeat >= heartbeat_interval_seconds():
                    updated_at = _coerce_epoch(current_job.get("updated_at"), now)
                    since_update = max(0.0, now - updated_at)
                    stalled = (
                        status == "running"
                        and since_update >= FeatureFlags.STALLED_THRESHOLD_SECONDS()
                    )
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

        async def event_stream() -> Any:
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
    """Stream real-time job execution stage transitions, metrics, and consistent hashing topology."""
    if not FeatureFlags.ENABLE_SSE_PROGRESS():
        raise HTTPException(
            status_code=501,
            detail="SSE progress streaming is disabled. Set ENABLE_SSE_PROGRESS=true",
        )

    job = await get_enriched_job(job_id, services)
    tenant_id = (_auth or {}).get("tenant_id", "default")
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    job_target = str(job.get("target_name") or job.get("hostname") or job.get("target") or "")
    if not is_target_owned_by_tenant(job_target, tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    from src.dashboard.registry import STAGE_LABELS

    emitter = SSEEventEmitter(job_id)
    request.headers.get("last-event-id", "")
    last_stage = job.get("stage", "")
    last_iteration = job.get("iteration", 0)

    async def progress_event_stream() -> AsyncGenerator[str]:
        nonlocal last_stage, last_iteration
        last_heartbeat = time.time()
        last_mesh_health = 0.0
        last_telemetry_count = 0

        event_chan: asyncio.Queue[str] = asyncio.Queue()

        # 1. Subscribe to asynchronous pipeline events
        from src.core.events import EventType, get_event_bus

        async def on_migration(event: Any) -> None:
            # We filter by job_id if present, otherwise broadcast to all active streams
            msg_job_id = event.data.get("job_id")
            if not msg_job_id or msg_job_id == job_id:
                await event_chan.put(emitter.migration_event(event.data))

        sub_id = get_event_bus().subscribe_async(EventType.GHOST_ACTOR_MIGRATED, on_migration)

        try:
            while True:
                if await request.is_disconnected():
                    break

                # 2. Check for queued async events
                while not event_chan.empty():
                    yield await event_chan.get()

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
                job_snapshot = snapshot_job_api(current_job)
                telemetry_events = job_snapshot.get("telemetry_events")
                if (
                    isinstance(telemetry_events, list)
                    and len(telemetry_events) > last_telemetry_count
                ):
                    for telemetry in telemetry_events[last_telemetry_count:]:
                        if isinstance(telemetry, dict):
                            yield emitter.telemetry_event(telemetry)
                    last_telemetry_count = len(telemetry_events)

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
                stage_entry = current_stage_entry(job_snapshot)
                yield emitter.progress_update(
                    stage=stage,
                    stage_label=stage_label,
                    progress_percent=progress,
                    message=current_job.get("status_message", ""),
                    stage_processed=processed,
                    stage_total=total,
                    stage_percent=current_stage_percent(job_snapshot, stage_entry),
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
                    telemetry_events=telemetry_events[-25:]
                    if isinstance(telemetry_events, list)
                    else None,
                )

                current_iteration = current_job.get("iteration", 0)
                if current_iteration != last_iteration:
                    max_iterations = current_job.get("max_iterations", 0)
                    stage_percent = current_stage_percent(job_snapshot, stage_entry)
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

                if now - last_heartbeat >= heartbeat_interval_seconds():
                    from src.dashboard.job_state import _coerce_epoch

                    updated_at = _coerce_epoch(current_job.get("updated_at"), now)
                    since_update = now - updated_at
                    stalled = (
                        status == "running"
                        and since_update >= FeatureFlags.STALLED_THRESHOLD_SECONDS()
                    )
                    yield emitter.heartbeat(
                        progress_percent=progress,
                        stage=stage,
                        stage_label=stage_label,
                        stalled=stalled,
                        seconds_since_last_update=since_update,
                    )
                    last_heartbeat = now

                await asyncio.sleep(1.0)
        finally:
            from src.core.events import get_event_bus

            try:
                get_event_bus().unsubscribe(sub_id)
            except Exception as e:
                logger.debug("Failed to unsubscribe from event bus: %s", e)

    return StreamingResponse(
        progress_event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

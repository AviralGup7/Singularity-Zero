"""SSE streaming endpoint for job log artifacts."""

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.jobs.artifacts import get_cached_job
from src.dashboard.fastapi.routers.utils import (
    current_stage_entry,
    current_stage_percent,
    heartbeat_interval_seconds,
    job_target_name,
    snapshot_job_api,
)
from src.dashboard.fastapi.schemas import ErrorResponse
from src.dashboard.feature_flags import FeatureFlags

# Bug #32 fix: import STAGE_LABELS at module scope so both branches of the
# ENABLE_SSE_PROGRESS flag can reference it without a NameError.
try:
    from src.dashboard.registry import STAGE_LABELS  # noqa: F401
except ImportError:
    STAGE_LABELS = {}  # type: ignore[assignment]

from src.dashboard.fastapi.routers.sse_events import SSEEventEmitter, _global_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["Jobs"])


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

    job = await get_cached_job(job_id, services)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not is_target_owned_by_tenant(job_target_name(job), tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    last_count = len(job.get("latest_logs", []))
    last_stage = job.get("stage", "")
    last_iteration = job.get("iteration", 0)

    last_event_id = request.headers.get("last-event-id", "")
    if last_event_id and last_event_id.startswith(f"{job_id}:"):
        parts = last_event_id.split(":")
        if len(parts) >= 6:
            try:
                last_count = int(parts[3])
                last_stage = parts[4].replace("_", ":")
                last_iteration = int(parts[5])
            except (ValueError, TypeError):
                pass
        elif len(parts) >= 5:
            try:
                last_count = int(parts[3])
                last_stage = parts[4].replace("_", ":")
            except (ValueError, TypeError):
                pass

    if FeatureFlags.ENABLE_SSE_PROGRESS():
        emitter = SSEEventEmitter(job_id)
        emitter.last_count = last_count
        emitter.last_stage = last_stage
        emitter.last_iteration = last_iteration
        last_stage = job.get("stage", "")

        async def typed_event_stream() -> Any:
            nonlocal last_count, last_stage
            from src.dashboard.job_state import _coerce_epoch

            _tracker_key = f"{job_id}:logs"
            _global_tracker.register_client(_tracker_key)

            last_heartbeat = time.time()
            last_telemetry_count = 0
            last_progress_data: dict[str, Any] = {}

            try:
                while True:
                    if await request.is_disconnected():
                        break

                    try:
                        current_job = await get_cached_job(job_id, services)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("get_cached_job failed in logs stream: %s", exc)
                        yield emitter.error(
                            "Failed to fetch job state",
                            stage=last_stage,
                            progress_percent=0,
                            recoverable=True,
                        )
                        await asyncio.sleep(1.0)
                        continue
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
                        emitter.last_stage = stage

                    logs = current_job.get("latest_logs", [])
                    if len(logs) > last_count:
                        new_logs = logs[last_count:]
                        last_count = len(logs)
                        emitter.last_count = last_count
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

                    current_data = {
                        "stage": stage,
                        "stage_label": stage_label,
                        "progress_percent": progress,
                        "message": current_job.get("status_message", ""),
                        "stage_processed": processed,
                        "stage_total": total,
                        "stage_percent": current_stage_percent(job_snapshot, stage_entry),
                        "status": current_job.get("status"),
                        "failed_stage": current_job.get("failed_stage") or None,
                        "failure_reason_code": current_job.get("failure_reason_code") or None,
                        "failure_step": current_job.get("failure_step") or None,
                        "failure_reason": current_job.get("failure_reason") or None,
                        "stage_status": (stage_entry or {}).get("status")
                        if isinstance(stage_entry, dict)
                        else None,
                        "stage_reason": (stage_entry or {}).get("reason")
                        if isinstance(stage_entry, dict)
                        else None,
                        "stage_error": (stage_entry or {}).get("error")
                        if isinstance(stage_entry, dict)
                        else None,
                        "retry_count": (stage_entry or {}).get("retry_count")
                        if isinstance(stage_entry, dict)
                        else None,
                        "stage_progress": job_snapshot.get("stage_progress")
                        if isinstance(job_snapshot.get("stage_progress"), list)
                        else None,
                        "progress_telemetry": job_snapshot.get("progress_telemetry")
                        if isinstance(job_snapshot.get("progress_telemetry"), dict)
                        else None,
                        "telemetry_events": telemetry_events[-25:]
                        if isinstance(telemetry_events, list)
                        else None,
                    }

                    if current_data != last_progress_data:
                        yield emitter.progress_update(
                            stage=stage,
                            stage_label=stage_label,
                            progress_percent=progress,
                            message=current_job.get("status_message", ""),
                            stage_processed=processed,
                            stage_total=total,
                            stage_percent=current_data["stage_percent"],
                            status=current_data["status"],
                            failed_stage=current_data["failed_stage"],
                            failure_reason_code=current_data["failure_reason_code"],
                            failure_step=current_data["failure_step"],
                            failure_reason=current_data["failure_reason"],
                            stage_status=current_data["stage_status"],
                            stage_reason=current_data["stage_reason"],
                            stage_error=current_data["stage_error"],
                            retry_count=current_data["retry_count"],
                            stage_progress=current_data["stage_progress"],
                            progress_telemetry=current_data["progress_telemetry"],
                            telemetry_events=current_data["telemetry_events"],
                            state_version=state_version,
                        )
                        last_progress_data = current_data

                    if status in ("completed", "failed", "stopped"):
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
                        if started_at is None or finished_or_now is None:
                            elapsed = None
                        else:
                            elapsed = max(0.0, finished_or_now - started_at)
                        yield emitter.completed(
                            status=status,
                            progress_percent=100 if status == "completed" else progress,
                            stage=stage,
                            stage_label=stage_label,
                            total_duration_seconds=(
                                round(elapsed, 1) if elapsed is not None else None
                            ),
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
            finally:
                _global_tracker.deregister_client(_tracker_key)

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
            _tracker_key = f"{job_id}:logs_legacy"
            _global_tracker.register_client(_tracker_key)
            try:
                while True:
                    if await request.is_disconnected():
                        break

                    try:
                        current_job = await get_cached_job(job_id, services)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("get_cached_job failed in legacy logs stream: %s", exc)
                        yield f"event: error\ndata: {json.dumps({'error': 'Failed to fetch job state'})}\n\n"
                        await asyncio.sleep(1.0)
                        continue
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
            finally:
                _global_tracker.deregister_client(_tracker_key)

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

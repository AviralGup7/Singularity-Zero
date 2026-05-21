"""Endpoint for retrieving job execution timeline."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs")


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

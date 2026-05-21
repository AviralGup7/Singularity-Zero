"""Endpoint for restarting a scan job with safe defaults."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import snapshot_job_api
from src.dashboard.fastapi.schemas import ErrorResponse, JobResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs")


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
        return JobResponse(**snapshot_job_api(result))
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    except Exception as exc:
        logger.exception("Failed to restart job %s: %s", job_id, exc)
        raise HTTPException(status_code=500, detail="Failed to restart job")

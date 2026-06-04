"""Endpoint for restarting a scan job with safe defaults."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_worker
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
    _auth: Any = Depends(require_worker),
    services: Any = Depends(get_queue_client),
) -> JobResponse:
    tenant_id = (_auth or {}).get("tenant_id", "default")
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    job = services.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job_target = str(job.get("target_name") or job.get("hostname") or job.get("target") or "")
    if not is_target_owned_by_tenant(job_target, tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        result = services.restart_job_safe(job_id)
        return JobResponse(**snapshot_job_api(result))
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")
    except Exception as exc:
        logger.exception("Failed to restart job %s: %s", job_id, exc)
        raise HTTPException(status_code=500, detail="Failed to restart job")

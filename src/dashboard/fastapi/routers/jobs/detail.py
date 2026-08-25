"""Endpoint for retrieving detailed job information."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
from src.dashboard.fastapi.routers.utils import get_enriched_job, job_target_name, snapshot_job_api
from src.dashboard.fastapi.schemas import ErrorResponse, JobResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs")


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
    tenant_id = (_auth or {}).get("tenant_id", "default")
    logger.debug("get_job job_id=%s tenant=%s", job_id, tenant_id)
    job = await get_enriched_job(job_id, services)
    target_name = job_target_name(job)
    if not is_target_owned_by_tenant(target_name, tenant_id):
        logger.warning(
            "[404] source=tenant_filter job_id=%s tenant=%s target=%s",
            job_id,
            tenant_id,
            target_name,
        )
        raise HTTPException(status_code=404, detail="Job not found")

    return JobResponse(**snapshot_job_api(job))

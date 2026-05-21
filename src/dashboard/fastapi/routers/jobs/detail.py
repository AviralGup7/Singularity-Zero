"""Endpoint for retrieving detailed job information."""

from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_enriched_job, snapshot_job_api
from src.dashboard.fastapi.schemas import ErrorResponse, JobResponse

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
    """Retrieve detailed execution metadata and status for a single job."""
    job = await get_enriched_job(job_id, services)
    return JobResponse(**snapshot_job_api(job))

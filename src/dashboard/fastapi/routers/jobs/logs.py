"""Endpoint for retrieving job logs."""

from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_enriched_job
from src.dashboard.fastapi.schemas import ErrorResponse, JobLogsResponse

router = APIRouter(prefix="/api/jobs")


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
    """Retrieve all logged process outputs captured during a job execution."""
    job = await get_enriched_job(job_id, services)
    return JobLogsResponse(
        job_id=job_id,
        logs=job.get("latest_logs", []),
        total_logs=len(job.get("latest_logs", [])),
        status=job.get("status"),
    )

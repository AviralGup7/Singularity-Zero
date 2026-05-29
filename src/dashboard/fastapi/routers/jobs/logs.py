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
    tenant_id = (_auth or {}).get("tenant_id", "default")
    from fastapi import HTTPException

    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    job = await get_enriched_job(job_id, services)
    job_target = str(job.get("target_name") or job.get("hostname") or job.get("target") or "")
    if not is_target_owned_by_tenant(job_target, tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    return JobLogsResponse(
        job_id=job_id,
        logs=job.get("latest_logs", []),
        total_logs=len(job.get("latest_logs", [])),
        status=job.get("status"),
    )

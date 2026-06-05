"""Endpoint for listing security scan jobs."""

from typing import Any

from fastapi import APIRouter, Depends, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
from src.dashboard.fastapi.routers.utils import job_target_name, snapshot_job_api
from src.dashboard.fastapi.schemas import ErrorResponse, JobListResponse, JobResponse
from src.dashboard.job_state import _coerce_epoch

router = APIRouter(prefix="/api/jobs")


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
    """List all scan jobs with sorting, filtering and pagination."""
    all_jobs = services.list_jobs()

    tenant_id = (_auth or {}).get("tenant_id", "default")

    all_jobs = [j for j in all_jobs if is_target_owned_by_tenant(job_target_name(j), tenant_id)]

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
        jobs=[JobResponse(**snapshot_job_api(j)) for j in page_jobs],
        total=total,
    )

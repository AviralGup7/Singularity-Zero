"""Endpoint for retrieving job failure remediation suggestions."""

from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_enriched_job
from src.dashboard.fastapi.schemas import ErrorResponse

router = APIRouter(prefix="/api/jobs")


@router.get(
    "/{job_id}/remediation",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get fix-command suggestions for a failed job",
)
async def get_job_remediation(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Compile diagnostic advice and precise command remediations for failed pipelines."""
    from src.dashboard.remediation import suggest_for_job

    job = await get_enriched_job(job_id, services)
    return {"job_id": job_id, "suggestions": suggest_for_job(job)}

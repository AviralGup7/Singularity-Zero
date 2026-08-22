"""Endpoint for retrieving job logs."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
from src.dashboard.fastapi.routers.utils import get_enriched_job, job_target_name
from src.dashboard.fastapi.schemas import ErrorResponse, JobLogsResponse

logger = logging.getLogger(__name__)

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
    job = await get_enriched_job(job_id, services)
    if not is_target_owned_by_tenant(job_target_name(job), tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    from pathlib import Path

    from src.dashboard.fastapi.dependencies import get_config

    config = get_config()
    output_root = Path(config.output_root).resolve()
    launcher_dir = (output_root / "launcher" / job_id).resolve()
    if not launcher_dir.is_relative_to(output_root):
        raise HTTPException(status_code=404, detail="Job not found")
    if not launcher_dir.exists() or not launcher_dir.is_dir():
        fallback = (output_root / "_launcher" / job_id).resolve()
        if fallback.is_relative_to(output_root):
            launcher_dir = fallback
    stdout_path = launcher_dir / "stdout.txt"

    total_logs = 0
    if stdout_path.exists() and stdout_path.is_file():
        try:
            with open(stdout_path, encoding="utf-8", errors="replace") as f:
                for _ in f:
                    total_logs += 1
        except OSError as exc:
            logger.warning("Could not count stdout lines for %s: %s", job_id, exc)
            total_logs = len(job.get("latest_logs", []))
    else:
        total_logs = len(job.get("latest_logs", []))

    return JobLogsResponse(
        job_id=job_id,
        logs=job.get("latest_logs", []),
        total_logs=total_logs,
        status=job.get("status"),
    )

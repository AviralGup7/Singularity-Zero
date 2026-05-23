"""Endpoint for starting a scan job."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import check_rate_limit, get_queue_client, require_worker
from src.dashboard.fastapi.schemas import ErrorResponse, JobCreateRequest, JobResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs")


@router.post(
    "",
    response_model=JobResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Start a new scan job",
)
@router.post(
    "/start",
    response_model=JobResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Start a new scan job",
)
async def start_job(
    request: JobCreateRequest,
    _auth: Any = Depends(require_worker),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> JobResponse:
    """Start a new pipeline scan job.

    Creates a job record, writes config/scope files, and launches
    the pipeline subprocess in a background thread.
    """
    try:
        result = services.start(
            request.base_url,
            scope_text=request.scope_text,
            selected_modules=request.modules,
            mode_name=request.mode,
            runtime_overrides=request.runtime_overrides or None,
            execution_options=request.execution_options or None,
        )
        return JobResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to start job: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to start job")

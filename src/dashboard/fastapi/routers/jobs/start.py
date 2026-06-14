"""Endpoint for starting a scan job."""

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import check_rate_limit, get_queue_client, require_worker
from src.dashboard.fastapi.schemas import ErrorResponse, JobCreateRequest, JobResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs")

CONFIGS_DIR = Path(__file__).resolve().parents[5] / "configs"


def _load_project_config(project_id: str) -> tuple[dict[str, Any], str]:
    """Load a project preset config and scope."""
    cfg_path = CONFIGS_DIR / f"{project_id}.json"
    scope_path = CONFIGS_DIR / f"{project_id}_scope.txt"

    if not cfg_path.is_file():
        raise ValueError(f"Project '{project_id}' not found")

    config = json.loads(cfg_path.read_text(encoding="utf-8"))
    # Strip _project metadata before passing to pipeline
    config.pop("_project", None)

    scope_text = ""
    if scope_path.is_file():
        scope_text = scope_path.read_text(encoding="utf-8")

    return config, scope_text


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
        # If project_id is provided, load the project config
        project_config = None
        project_scope = ""
        if request.project_id:
            project_config, project_scope = _load_project_config(request.project_id)
            # Use project scope as fallback if no scope provided
            if not request.scope_text.strip():
                request.scope_text = project_scope

        result = services.start(
            request.base_url,
            scope_text=request.scope_text,
            selected_modules=request.modules,
            mode_name=request.mode,
            runtime_overrides=request.runtime_overrides or None,
            execution_options=request.execution_options or None,
            project_config=project_config,
        )
        return JobResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to start job: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to start job")

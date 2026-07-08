"""Endpoint for starting a scan job.

Bug #37: Project config is now validated against a known schema before
injection into the pipeline. Unknown or dangerous keys are stripped to
prevent project presets from silently altering pipeline behavior.

Bug #38: A config fingerprint (SHA-256 of the serialized config) is
stored with the job so resume logic can detect config drift.
"""

import hashlib
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

# Bug #37: Known config keys that project presets are allowed to set.
# Any key not in this set is stripped and logged to prevent silent
# pipeline behavior changes from malicious or misconfigured presets.
_PROJECT_CONFIG_ALLOWLIST = {
    "analysis",
    "http_timeout_seconds",
    "mode",
    "max_response_bytes",
    "max_live_hosts",
    "max_priority_urls",
    "max_workers",
    "request_rate_per_second",
    "request_burst",
    "auto_max_speed_mode",
    "response_cache_ttl_hours",
    "enable_idor_comparison",
    "idor_compare_limit",
    "idor_compare_similarity_threshold",
    "adaptive_retry_attempts",
    "adaptive_max_rate_per_second",
    "adaptive_max_burst",
    "adaptive_min_rate_per_second",
    "rebalance_group_factor",
    "tools",
    "modules",
    "target_name",
}


def _load_project_config(project_id: str) -> tuple[dict[str, Any], str]:
    """Load a project preset config and scope.

    Bug #37: Validates the config against an allowlist before returning.
    Unknown keys are stripped and logged to prevent project presets from
    injecting unexpected behavior into the pipeline.
    """
    cfg_path = CONFIGS_DIR / f"{project_id}.json"
    scope_path = CONFIGS_DIR / f"{project_id}_scope.txt"

    if not cfg_path.is_file():
        raise ValueError(f"Project '{project_id}' not found")

    config = json.loads(cfg_path.read_text(encoding="utf-8"))
    # Strip _project metadata before passing to pipeline
    config.pop("_project", None)

    # Bug #37: Validate config keys against allowlist
    unknown_keys = set(config.keys()) - _PROJECT_CONFIG_ALLOWLIST
    if unknown_keys:
        logger.warning(
            "Project '%s' config contains unknown keys that will be stripped: %s",
            project_id,
            sorted(unknown_keys),
        )
        for key in unknown_keys:
            config.pop(key, None)

    scope_text = ""
    if scope_path.is_file():
        scope_text = scope_path.read_text(encoding="utf-8")

    return config, scope_text


def _config_fingerprint(config: dict[str, Any]) -> str:
    """Bug #38: Compute a SHA-256 fingerprint of the config for resume drift detection.

    The fingerprint is stored with the job so that if a job is resumed,
    the resume logic can compare the current config against the original
    and warn if they differ (which would indicate mixed execution semantics).
    """
    canonical = json.dumps(config, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


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

    Bug #38: Attaches a config fingerprint to the job metadata so
    resume logic can detect if the config changed between runs.
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

        # Bug #38: Compute config fingerprint for resume drift detection
        config_fingerprint = None
        if project_config is not None:
            config_fingerprint = _config_fingerprint(project_config)

        result = services.start(
            request.base_url,
            scope_text=request.scope_text,
            selected_modules=request.modules,
            mode_name=request.mode,
            runtime_overrides=request.runtime_overrides or None,
            execution_options=request.execution_options or None,
            project_config=project_config,
            config_fingerprint=config_fingerprint,
        )
        return JobResponse(**result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to start job: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to start job")

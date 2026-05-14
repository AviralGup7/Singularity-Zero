"""Request replay endpoint for the FastAPI dashboard."""

import logging
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query
from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import ErrorResponse, ReplayResponse
from src.dashboard.fastapi.validation import (
    is_safe_replay_url,
    is_within_directory,
    validate_replay_id,
    validate_run_name,
    validate_target_name,
)





router = APIRouter(prefix="/api/replay", tags=["Replay"])


logger = logging.getLogger(__name__)


@router.get(
    "",
    response_model=ReplayResponse,
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
    },
    summary="Replay a captured request",
)
async def replay_request(
    target: str = Query(..., description="Target name"),
    run: str = Query(..., description="Run name"),
    replay_id: str = Query(..., description="Replay ID"),
    auth_mode: str = Query("inherit", description="Authentication mode"),
    authorization: str = Query("", description="Authorization header value"),
    cookie: str = Query("", description="Cookie value"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> ReplayResponse:
    """Replay a previously captured request and compare responses."""
    from src.analysis.behavior.analysis_support import compare_response_records
    from src.analysis.behavior.artifacts import load_plugin_artifact, plugin_artifact_path
    from src.analysis.passive.runtime import fetch_response
    from src.execution.exploiters.exploit_automation import replay_headers_for_mode

    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name.")
    if not validate_run_name(run):
        raise HTTPException(status_code=400, detail="Invalid run name.")
    if not validate_replay_id(replay_id):
        raise HTTPException(status_code=400, detail="Invalid replay ID.")

    output_root = services.query.output_root
    run_dir = (output_root / target / run).resolve()
    behavior_path = plugin_artifact_path(run_dir, "behavior_analysis_layer").resolve()
    legacy_path = (run_dir / "behavior_analysis_layer.json").resolve()

    if not is_within_directory(output_root, run_dir) or (
        not behavior_path.exists() and not legacy_path.exists()
    ):
        raise HTTPException(status_code=404, detail="Replay context not found.")

    records = load_plugin_artifact(run_dir, "behavior_analysis_layer")
    if not isinstance(records, list):
        raise HTTPException(status_code=500, detail="Replay context could not be loaded.")

    item = next(
        (entry for entry in records if str(entry.get("replay", {}).get("id", "")) == replay_id),
        None,
    )
    if not isinstance(item, dict):
        raise HTTPException(status_code=404, detail="Replay id not found.")

    request_context = item.get("request_context", {})
    baseline_url = str(request_context.get("baseline_url", "")).strip()
    mutated_url = str(request_context.get("mutated_url", "")).strip()

    if not mutated_url:
        raise HTTPException(status_code=400, detail="Stored request context is incomplete.")

    try:
        extra_headers = replay_headers_for_mode(
            auth_mode, authorization=authorization, cookie=cookie
        )
    except ValueError as exc:
        logger.exception("Replay header generation failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    if baseline_url and not is_safe_replay_url(baseline_url):
        raise HTTPException(status_code=400, detail="Replay URL targets a restricted network.")
    if not is_safe_replay_url(mutated_url):
        raise HTTPException(status_code=400, detail="Replay URL targets a restricted network.")

    try:
        baseline = (
            fetch_response(
                baseline_url, timeout_seconds=12, max_bytes=120000, extra_headers=extra_headers
            )
            if baseline_url
            else None
        )
    except Exception as exc:
        logger.warning("Baseline fetch failed for replay %s: %s", replay_id, exc)
        baseline = None

    try:
        replay = fetch_response(
            mutated_url, timeout_seconds=12, max_bytes=120000, extra_headers=extra_headers
        )
    except Exception as exc:
        logger.warning("Replay fetch failed for %s: %s", replay_id, exc)
        raise HTTPException(status_code=502, detail=str(exc))

    if not replay:
        raise HTTPException(status_code=502, detail="Replay request did not return a response.")

    diff = compare_response_records(baseline, replay) if baseline else {}

    return ReplayResponse(
        replay_id=replay_id,
        auth_mode=auth_mode,
        applied_header_names=sorted(extra_headers),
        requested_url=replay.get("requested_url", mutated_url),
        final_url=replay.get("url", mutated_url),
        redirect_chain=replay.get("redirect_chain", []),
        status_code=replay.get("status_code"),
        body_similarity=diff.get("body_similarity"),
        status_changed=diff.get("status_changed"),
        redirect_changed=diff.get("redirect_changed"),
        content_changed=diff.get("content_changed"),
    )

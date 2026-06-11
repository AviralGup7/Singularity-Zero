"""Cockpit API endpoints for events and sandbox operations."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from src.dashboard.fastapi.dependencies import check_rate_limit, get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cockpit", tags=["Cockpit"])


@router.get(
    "/events",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get cockpit event timeline",
)
async def get_cockpit_events(
    target: str = Query(..., min_length=1),
    run: str | None = Query(None),
    job_id: str | None = Query(None),
    cursor: str | None = Query(None),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Return a timeline of cockpit-relevant events."""
    output_root = services.query.output_root
    get_safe_target_dir(output_root, target)

    timeline = services.query.get_timeline_data(target)

    from src.pipeline.analyst_notes import get_all_notes

    notes = get_all_notes(target, output_dir=output_root)

    events = []
    for f in timeline:
        events.append(
            {
                "id": f.get("finding_id"),
                "type": "finding",
                "timestamp": f.get("timestamp"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "url": f.get("url"),
            }
        )

    for n in notes:
        events.append(
            {
                "id": n.note_id,
                "type": "note",
                "timestamp": n.created_at,
                "author": n.author,
                "note": n.note,
                "finding_id": n.finding_id,
            }
        )

    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"events": events[:100], "next_cursor": None}


class SandboxLaunchRequest(BaseModel):
    target_node: str
    image: str = "ubuntu:latest"


class TerminalCommandRequest(BaseModel):
    command: str


@router.post(
    "/probes",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Trigger a manual forensic probe",
)
async def trigger_cockpit_probe(
    target: str = Query(..., min_length=1),
    url: str = Query(..., min_length=1),
    method: str = "GET",
    _auth: Any = Depends(require_auth),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Trigger a manual probe with scope validation and forensic capture."""
    from src.analysis.passive.runtime import _get_fetch_response

    fetch_response = _get_fetch_response()
    from src.core.utils.url_validation import is_safe_url

    output_root = services.query.output_root
    get_safe_target_dir(output_root, target)

    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL is out of scope or unsafe")

    try:
        result = fetch_response(
            url,
            timeout_seconds=15,
            max_bytes=1024 * 512,
            method=method.upper(),
            capture_forensics=True,
            output_dir=output_root,
            target_name=target,
        )
    except Exception as e:
        logger.error("Manual probe failed: %s", e)
        raise HTTPException(status_code=502, detail=f"Probe failed: {str(e)}")

    if not result:
        raise HTTPException(status_code=502, detail="Probe did not return a response")

    return {
        "status": "success",
        "exchange_id": str(result.get("exchange_id", "")),
        "status_code": int(result.get("status_code", 0)),
        "url": str(result.get("url", "")),
    }


@router.post(
    "/sandbox/launch",
    summary="Launch a safe dockerized sandbox for a node",
)
async def launch_sandbox(
    request: SandboxLaunchRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    from src.dashboard.fastapi.sandbox_service import sandbox_manager

    sandbox_id = sandbox_manager.launch_sandbox(request.target_node, request.image)
    return {"status": "success", "sandbox_id": sandbox_id}


@router.get(
    "/sandbox/{sandbox_id}/state",
    summary="View chronological state of the sandbox for Time-Travel Replay",
)
async def get_sandbox_state(
    sandbox_id: str,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    from src.dashboard.fastapi.sandbox_service import sandbox_manager

    history = sandbox_manager.get_chronological_state(sandbox_id)
    return {"status": "success", "history": history}


@router.post(
    "/sandbox/{sandbox_id}/terminal",
    summary="Execute manual command in the sandbox terminal",
)
async def execute_terminal(
    sandbox_id: str,
    request: TerminalCommandRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    from src.dashboard.fastapi.sandbox_service import sandbox_manager

    try:
        output = sandbox_manager.execute_terminal_command(sandbox_id, request.command)
        return {"status": "success", "output": output}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

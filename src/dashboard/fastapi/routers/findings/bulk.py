import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings.crud import update_finding
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.put(
    "/bulk",
    response_model=list[dict[str, Any]],
    responses={401: {"model": ErrorResponse}},
    summary="Bulk update findings",
)
async def bulk_update_findings(
    payload: dict[str, Any],
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> list[dict[str, Any]]:
    """Apply updates to multiple findings."""
    ids = payload.get("ids", [])
    ALLOWED_BULK_UPDATE_FIELDS = {
        "status",
        "severity",
        "decision",
        "notes",
        "lifecycle_state",
        "assignee",
        "tags",
    }
    raw_updates = {k: v for k, v in payload.items() if k != "ids"}
    updates = {k: v for k, v in raw_updates.items() if k in ALLOWED_BULK_UPDATE_FIELDS}
    if len(updates) != len(raw_updates):
        rejected = set(raw_updates) - ALLOWED_BULK_UPDATE_FIELDS
        logger.warning("Bulk update: rejecting disallowed fields: %s", sorted(rejected))
    results = []

    for fid in ids:
        try:
            res = await update_finding(fid, updates, _auth=_auth, services=services)
            results.append(res)
        except HTTPException:
            continue

    return results

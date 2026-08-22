import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings.crud import update_finding
from src.dashboard.fastapi.routers.findings.field_map import map_update_payload
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
    if not isinstance(ids, list) or not ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list")
    raw_updates = {k: v for k, v in payload.items() if k != "ids"}
    updates = map_update_payload(raw_updates, bulk=True)
    rejected = set(raw_updates) - set(updates)
    if rejected:
        logger.warning("Bulk update: rejecting disallowed fields: %s", sorted(rejected))
    if not updates:
        raise HTTPException(status_code=400, detail="No permitted fields to update")
    results = []

    for fid in ids:
        try:
            res = await update_finding(str(fid), updates, _auth=_auth, services=services)
            results.append(res)
        except HTTPException as exc:
            logger.warning("Bulk update skipped %s: %s", fid, exc.detail)
        except Exception:
            logger.exception("Bulk update failed for %s", fid)

    return results

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_admin
from src.dashboard.fastapi.routers.findings.crud import (
    _atomic_write_json,
    _locate_finding_on_disk,
    _lock_for,
)
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.delete(
    "/{finding_id}",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Delete a finding",
)
async def delete_finding(
    finding_id: str,
    _auth: Any = Depends(require_admin),
    services: Any = Depends(get_queue_client),
) -> dict[str, bool]:
    """Remove a finding from disk."""
    output_root = services.query.output_root
    tenant_id = (_auth or {}).get("tenant_id", "default")
    located = _locate_finding_on_disk(output_root, finding_id, tenant_id)
    if not located:
        raise HTTPException(status_code=404, detail="Finding not found")
    _, _, target_finding_idx, _, findings_list, findings_file_path = located

    try:
        lock = _lock_for(findings_file_path)
        with lock:
            findings_list.pop(target_finding_idx)
            _atomic_write_json(findings_file_path, findings_list)
    except PermissionError as exc:
        logger.error("Permission denied deleting finding %s: %s", finding_id, exc)
        raise HTTPException(status_code=409, detail="Finding file is not writable") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Finding file disappeared") from exc
    except OSError as exc:
        logger.error("Failed to delete finding: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to delete finding from disk") from exc

    return {"success": True}

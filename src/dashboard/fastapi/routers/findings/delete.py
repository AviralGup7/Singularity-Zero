import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_admin
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


def _locate_finding_on_disk(
    output_root: Any, finding_id: str, tenant_id: str
) -> tuple[str, str, int, dict[str, Any], list[dict[str, Any]], Any] | None:
    for target_entry in output_root.iterdir():
        if not target_entry.is_dir():
            continue
        from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

        if not is_target_owned_by_tenant(target_entry.name, tenant_id):
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir():
                continue
            findings_path = run_entry / "findings.json"
            if not findings_path.exists():
                continue
            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: S112
                continue
            for idx, f in enumerate(findings):
                fid = (
                    f.get("id")
                    or f.get("finding_id")
                    or f"{target_entry.name}-{run_entry.name}-{idx + 1}"
                )
                if fid == finding_id:
                    return target_entry.name, run_entry.name, idx, f, findings, findings_path
    return None


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
        if findings_file_path:
            findings_list.pop(target_finding_idx)
            findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
        else:
            raise ValueError("Finding path not found")
    except Exception as e:
        logger.error("Failed to delete finding: %s", e)
        raise HTTPException(status_code=500, detail="Failed to delete finding from disk")

    return {"success": True}

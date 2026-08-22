import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings.field_map import map_update_payload
from src.dashboard.fastapi.routers.targets import _normalize_finding_payload
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


# Field allow-list lives in field_map so bulk + single-item updates stay aligned.


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
            except Exception:
                logger.warning("Failed to read findings file %s", findings_path, exc_info=True)
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


@router.put(
    "/{finding_id}",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Update a finding",
)
async def update_finding(
    finding_id: str,
    update_data: dict[str, Any],
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Update finding metadata (status, severity, etc.) on disk."""
    output_root = services.query.output_root
    tenant_id = (_auth or {}).get("tenant_id", "default")
    located = _locate_finding_on_disk(output_root, finding_id, tenant_id)
    if not located:
        raise HTTPException(status_code=404, detail="Finding not found")
    (
        target_name,
        run_name,
        target_finding_idx,
        finding_payload,
        findings_list,
        findings_file_path,
    ) = located

    # Bulk already mapped the body (including tombstones). Remap, but keep
    # ``_deleted`` when the caller already sent the persisted key.
    mapped = map_update_payload(update_data, bulk=bool(update_data.get("_deleted")))
    rejected = set(update_data) - set(mapped) - {"id", "finding_id", "ids"}
    if rejected:
        logger.warning("update_finding: ignoring disallowed fields %s", sorted(rejected))
    delete_requested = bool(mapped.pop("_deleted", False) or update_data.get("_deleted"))
    for key, value in mapped.items():
        finding_payload[key] = value
    if mapped.get("false_positive") and not finding_payload.get("fp_status"):
        finding_payload["fp_status"] = "approved"
    if mapped.get("false_positive") and not finding_payload.get("decision"):
        finding_payload["decision"] = "DROP"

    try:
        if not findings_file_path:
            raise ValueError("Finding path not found")
        if delete_requested:
            del findings_list[target_finding_idx]
            findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
            return {"id": finding_id, "deleted": True}
        findings_list[target_finding_idx] = finding_payload
        findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to save updated finding: %s", e)
        raise HTTPException(status_code=500, detail="Failed to persist finding update")

    _propagate_false_positive(finding_payload)

    return _normalize_finding_payload(
        finding_payload, target_name=target_name, run_name=run_name, index=target_finding_idx + 1
    )


def _propagate_false_positive(finding_payload: dict[str, Any]) -> None:
    """Propagate false-positive triage to the learning subsystem.

    Bug #1: The background task for FP tracking is now created via the
    TaskRegistry so it is properly tracked, cancelled on shutdown, and
    its exceptions are logged.  Previously, ``loop.create_task()`` created
    a fire-and-forget task that could silently fail or survive shutdown.
    """
    is_fp_triage = (
        finding_payload.get("decision") == "DROP"
        or finding_payload.get("status") == "false_positive"
        or finding_payload.get("lifecycle_state") == "FALSE_POSITIVE"
    )
    if not is_fp_triage:
        return
    try:
        from src.learning.integration import LearningIntegration

        learning = LearningIntegration.get_or_create()
        if not learning or not learning.config.enabled:
            return
        response_status = finding_payload.get("response_status") or finding_payload.get(
            "status_code"
        )
        body = (
            finding_payload.get("evidence")
            or finding_payload.get("body")
            or finding_payload.get("description", "")
        )
        category = finding_payload.get("category", "general")
        import asyncio

        async def _tracked_fp_update() -> None:
            try:
                await learning._fp_tracker.add_manual_fp(
                    category=category,
                    status_code=int(response_status) if response_status else None,
                    body_indicator=body,
                )
            except Exception as exc:
                logger.warning("FP tracker update failed: %s", exc)

        try:
            loop = asyncio.get_running_loop()
            # Bug #1: Register with TaskRegistry for proper lifecycle tracking
            try:
                from src.core.task_registry import get_task_registry

                get_task_registry().create_task(
                    _tracked_fp_update(),
                    owner="findings_crud",
                    name="fp_propagation",
                )
            except ImportError:
                loop.create_task(_tracked_fp_update())
        except RuntimeError:
            asyncio.run(_tracked_fp_update())
    except Exception as e:
        logger.warning("Mesh FP Sync: Failed to propagate manual FP: %s", e)

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.targets import _normalize_finding_payload
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


ALLOWED_UPDATE_FIELDS = {
    "status",
    "severity",
    "decision",
    "notes",
    "lifecycle_state",
    "assignee",
    "tags",
    "false_positive",
    "remediation_status",
    "remediation_notes",
}


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

    for key, value in update_data.items():
        if key in ALLOWED_UPDATE_FIELDS:
            finding_payload[key] = value
        elif key not in {"id", "finding_id"}:
            logger.warning("update_finding: ignoring disallowed field '%s'", key)

    try:
        if findings_file_path:
            findings_list[target_finding_idx] = finding_payload
            findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
        else:
            raise ValueError("Finding path not found")
    except Exception as e:
        logger.error("Failed to save updated finding: %s", e)
        raise HTTPException(status_code=500, detail="Failed to persist finding update")

    _propagate_false_positive(finding_payload)

    return _normalize_finding_payload(
        finding_payload, target_name=target_name, run_name=run_name, index=target_finding_idx + 1
    )


def _propagate_false_positive(finding_payload: dict[str, Any]) -> None:
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

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                learning._fp_tracker.add_manual_fp(
                    category=category,
                    status_code=int(response_status) if response_status else None,
                    body_indicator=body,
                )
            )
        except RuntimeError:
            asyncio.run(
                learning._fp_tracker.add_manual_fp(
                    category=category,
                    status_code=int(response_status) if response_status else None,
                    body_indicator=body,
                )
            )
    except Exception as e:
        logger.warning("Mesh FP Sync: Failed to propagate manual FP: %s", e)

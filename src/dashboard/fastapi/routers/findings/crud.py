import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings.field_map import coerce_bool, map_update_payload
from src.dashboard.fastapi.routers.findings.helpers import read_json_file
from src.dashboard.fastapi.routers.targets import _normalize_finding_payload, is_target_owned_by_tenant
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])

_WRITE_LOCKS: dict[str, threading.Lock] = {}
_WRITE_LOCKS_GUARD = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _WRITE_LOCKS_GUARD:
        lock = _WRITE_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _WRITE_LOCKS[key] = lock
        return lock


def _atomic_write_json(path: Path, payload: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _locate_finding_on_disk(
    output_root: Any, finding_id: str, tenant_id: str
) -> tuple[str, str, int, dict[str, Any], list[dict[str, Any]], Path] | None:
    for target_entry in output_root.iterdir():
        if not target_entry.is_dir() or target_entry.name.startswith("_"):
            continue
        if not is_target_owned_by_tenant(target_entry.name, tenant_id):
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir() or run_entry.name.startswith("_"):
                continue
            findings_path = run_entry / "findings.json"
            if not findings_path.exists():
                continue
            try:
                findings = read_json_file(findings_path)
            except (OSError, ValueError, json.JSONDecodeError):
                logger.warning("Failed to read findings file %s", findings_path, exc_info=True)
                continue
            if not isinstance(findings, list):
                continue
            for idx, finding in enumerate(findings):
                if not isinstance(finding, dict):
                    continue
                fid = (
                    finding.get("id")
                    or finding.get("finding_id")
                    or f"{target_entry.name}-{run_entry.name}-{idx + 1}"
                )
                if fid == finding_id:
                    return target_entry.name, run_entry.name, idx, finding, findings, findings_path
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

    mapped = map_update_payload(update_data, bulk=bool(update_data.get("_deleted")))
    rejected = set(update_data) - set(mapped) - {"id", "finding_id", "ids"}
    if rejected:
        logger.warning("update_finding: ignoring disallowed fields %s", sorted(rejected))
    delete_requested = coerce_bool(mapped.pop("_deleted", False) or update_data.get("_deleted"))
    updated = dict(finding_payload)
    for key, value in mapped.items():
        updated[key] = value
    if mapped.get("false_positive") and not updated.get("fp_status"):
        updated["fp_status"] = "approved"
    if mapped.get("false_positive") and not updated.get("decision"):
        updated["decision"] = "DROP"

    try:
        lock = _lock_for(findings_file_path)
        with lock:
            if delete_requested:
                del findings_list[target_finding_idx]
            else:
                findings_list[target_finding_idx] = updated
            _atomic_write_json(findings_file_path, findings_list)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to save updated finding: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to persist finding update") from exc

    if delete_requested:
        return {"id": finding_id, "deleted": True}

    _propagate_false_positive(updated)
    return _normalize_finding_payload(
        updated, target_name=target_name, run_name=run_name, index=target_finding_idx + 1
    )


def _propagate_false_positive(finding_payload: dict[str, Any]) -> None:
    """Propagate false-positive triage to the learning subsystem."""
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
        except RuntimeError:
            logger.debug("No running loop for FP propagation; skipping")
            return
        try:
            from src.core.task_registry import get_task_registry

            get_task_registry().create_task(
                _tracked_fp_update(),
                owner="findings_crud",
                name="fp_propagation",
            )
        except ImportError:
            loop.create_task(_tracked_fp_update())
    except Exception as exc:
        logger.warning("Mesh FP Sync: Failed to propagate manual FP: %s", exc)

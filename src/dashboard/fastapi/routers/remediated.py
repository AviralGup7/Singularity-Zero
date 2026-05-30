"""Remediation verification endpoints for the FastAPI dashboard."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from src.dashboard.fastapi.dependencies import check_rate_limit, get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings import _find_finding_by_id
from src.dashboard.fastapi.routers.targets import verify_tenant_boundary
from src.execution.remediators.remediation_scanner import RemediationScanner

router = APIRouter(prefix="/api/remediated", tags=["Remediation Verification"])

logger = logging.getLogger(__name__)


@router.post(
    "/{finding_id}/verify",
    response_model=dict[str, Any],
    responses={
        404: {"detail": "Finding not found"},
        401: {"detail": "Unauthorized"},
        403: {"detail": "Access denied"},
        429: {"detail": "Rate limit exceeded"},
    },
    summary="Verify whether a vulnerability finding has been remediated",
)
async def verify_finding_remediation(
    finding_id: str,
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
    _rate_limit: Any = Depends(check_rate_limit),
) -> dict[str, Any]:
    """Verify whether a finding has been remediated by re-running the AEVE PoC bundle."""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    user_role = (_auth or {}).get("role", "read")
    user_id = (_auth or {}).get("user", "unknown")

    # 1. Enforce Role Permissions
    if user_role not in {"admin", "write"}:
        raise HTTPException(
            status_code=403,
            detail="Access denied: user role must be admin or write to perform remediation verification.",
        )

    # 2. Locate finding by ID
    # Note: findings may be under different targets, so _find_finding_by_id locates them
    finding = _find_finding_by_id(services.query.output_root, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # 3. Enforce Tenant Boundaries
    target_name = finding.get("target") or finding.get("target_name") or ""
    verify_tenant_boundary(request, target_name, tenant_id, user_id)

    # 2. Get the raw findings file path to persist the updated status
    found = False
    findings_file_path = None
    findings_list = []
    target_finding_idx = -1

    output_root = services.query.output_root
    for target_entry in output_root.iterdir():
        if not target_entry.is_dir():
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir():
                continue
            findings_path = run_entry / "findings.json"
            if findings_path.exists():
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    for idx, f in enumerate(findings):
                        fid = (
                            f.get("id")
                            or f.get("finding_id")
                            or f"{target_entry.name}-{run_entry.name}-{idx + 1}"
                        )
                        if fid == finding_id:
                            found = True
                            target_finding_idx = idx
                            findings_list = findings
                            findings_file_path = findings_path
                            break
                except Exception:
                    continue
            if found:
                break
        if found:
            break

    if not found or not findings_file_path:
        raise HTTPException(status_code=404, detail="Finding not found")

    # 3. Instantiate RemediationScanner and execute verification
    scanner = RemediationScanner(use_wasm_sandbox=True)
    try:
        redis_client = (
            services.queue.client
            if hasattr(services, "queue") and hasattr(services.queue, "client")
            else None
        )

        # Note: verify_remediation enforces tenant_id check internally!
        result = await scanner.verify_remediation(
            finding,
            redis_client=redis_client,
            tenant_id=tenant_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed during remediation verification check: %s", exc)
        raise HTTPException(status_code=500, detail=f"Verification failed: {exc}")

    # If verification ran successfully (i.e. not on cooldown), persist the updated finding to disk
    if result.get("status") in {"success", "failed"}:
        updated_finding = result["finding"]

        # Remove internal/normalized helper fields before writing back to the raw JSON file
        clean_finding = dict(updated_finding)
        clean_finding.pop("target_name", None)
        clean_finding.pop("run_name", None)
        clean_finding.pop("finding_index", None)
        clean_finding.pop("generated_at_utc", None)

        try:
            findings_list[target_finding_idx] = clean_finding
            findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to write remediated finding update back to disk: %s", exc)
            raise HTTPException(
                status_code=500, detail="Failed to save remediation verification outcome to disk"
            )

    return result

"""Validation, tenant boundary checks, and finding normalization for targets."""

import logging
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def is_target_owned_by_tenant(target_name: str, tenant_id: str | None) -> bool:
    """Helper to enforce strict tenant boundary limits on targets."""
    if not tenant_id:
        tenant_id = "default"

    if target_name.startswith(f"{tenant_id}_"):
        return True

    if tenant_id == "default":
        if target_name.startswith("tenant") and "_" in target_name:
            parts = target_name.split("_", 1)
            if parts[0] != "default":
                return False
        return True

    return False


def verify_tenant_boundary(
    request: Request, target_name: str, tenant_id: str | None, user_id: str | None = None
) -> None:
    """Verify tenant boundary and log any violations to the security store as audit logs."""
    if not is_target_owned_by_tenant(target_name, tenant_id):
        store = getattr(request.app.state, "security_store", None)
        if store:
            try:
                store.record_event(
                    "tenant_violation",
                    status_code=403,
                    method=request.method,
                    path=request.url.path,
                    client_ip=request.client.host if request.client else "unknown",
                    detail={
                        "target_name": target_name,
                        "tenant_id": tenant_id or "default",
                        "user_id": user_id or "unknown",
                        "violation": "Attempted cross-tenant resource access",
                    },
                )
            except Exception as exc:
                logger.warning("Failed to record tenant violation event: %s", exc)
        raise HTTPException(status_code=403, detail="Access denied to this target")


def _validate_target_name(name: str) -> bool:
    from src.dashboard.fastapi.validation import validate_target_name

    return validate_target_name(name)


def _normalize_finding_payload(
    raw_finding: dict[str, Any],
    *,
    target_name: str,
    run_name: str,
    index: int,
    generated_at: str = "",
) -> dict[str, Any]:
    finding = dict(raw_finding)

    severity = str(finding.get("severity", "info")).strip().lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"

    status = str(finding.get("status", "open")).strip().lower()
    if status not in {"open", "closed", "accepted"}:
        status = "open"

    lifecycle_state = str(finding.get("lifecycle_state", "detected")).strip().lower()
    if lifecycle_state not in {"detected", "validated", "exploitable", "reportable"}:
        lifecycle_state = "detected"

    finding_type = (
        str(finding.get("type") or finding.get("category") or "finding").strip() or "finding"
    )

    description = str(finding.get("description") or finding.get("title") or finding_type).strip()

    finding_date = (
        str(finding.get("date") or finding.get("timestamp") or generated_at or run_name).strip()
        or run_name
    )

    finding_id = (
        str(
            finding.get("id") or finding.get("finding_id") or f"{target_name}-{run_name}-{index}"
        ).strip()
        or f"{target_name}-{run_name}-{index}"
    )

    normalized = {
        **finding,
        "id": finding_id,
        "severity": severity,
        "type": finding_type,
        "target": str(finding.get("target") or target_name).strip() or target_name,
        "status": status,
        "date": finding_date,
        "timestamp": finding.get("timestamp") or run_name,
        "description": description,
        "csi_score": finding.get("csi_score"),
        "logic_diff": finding.get("metadata", {}).get("diff")
        if "logic_breach" in finding_type.lower()
        else None,
    }
    return normalized


class TargetFindingsResponse(BaseModel):
    """Findings for a specific target."""

    findings: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    target: str = ""

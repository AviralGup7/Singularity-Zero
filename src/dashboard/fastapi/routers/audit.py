"""Audit log endpoints for the FastAPI dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.dashboard.fastapi.dependencies import require_admin
from src.dashboard.fastapi.schemas import ErrorResponse

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get(
    "/entries",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Get audit log entries",
)
async def get_audit_entries(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event: str | None = None,
    user_id: str | None = None,
    severity: str | None = None,
    _auth: Any = Depends(require_admin),
) -> list[dict[str, Any]]:
    """Return audit log entries with filtering and pagination."""
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger is None:
        raise HTTPException(status_code=503, detail="Audit logger is not initialized")

    entries = audit_logger.get_entries(
        limit=limit,
        offset=offset,
        event=event,
        user_id=user_id,
        severity=severity,
    )
    return [entry.model_dump() for entry in entries]


@router.get(
    "/verify",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Verify audit log integrity",
)
async def verify_audit_integrity(
    request: Request,
    _auth: Any = Depends(require_admin),
) -> dict[str, Any]:
    """Check the hash chain of the audit log to detect tampering."""
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger is None:
        raise HTTPException(status_code=503, detail="Audit logger is not initialized")

    is_valid, compromised_ids = audit_logger.verify_integrity()
    return {
        "is_valid": is_valid,
        "compromised_ids": compromised_ids,
        "entry_count": len(audit_logger.get_entries(limit=1000000)),
    }

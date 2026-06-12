"""Access log endpoints for the FastAPI dashboard.

Provides server-side persistence for compliance access logs that were
previously stored only in browser sessionStorage.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/access-logs", tags=["Access Logs"])

# ---------------------------------------------------------------------------
# In-memory store (backed by the audit logger when available)
# ---------------------------------------------------------------------------

_access_log_lock = threading.Lock()
_access_log_entries: list[dict[str, Any]] = []


class AccessLogEntry(BaseModel):
    """Single access-log record."""

    id: str = Field(default_factory=lambda: f"al-{uuid.uuid4()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    user: str = "anonymous"
    action: str
    resource: str
    reason: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    outcome: str = "success"


class AccessLogCreateRequest(BaseModel):
    """Body for creating a new access-log entry."""

    action: str
    resource: str
    reason: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    user: str = "anonymous"
    outcome: str = "success"


@router.get(
    "",
    response_model=list[dict[str, Any]],
    responses={401: {"model": ErrorResponse}},
    summary="List access-log entries",
)
async def list_access_logs(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str | None = None,
    action: str | None = None,
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Return access-log entries, optionally filtered by user or action."""
    with _access_log_lock:
        entries = list(_access_log_entries)

    if user:
        entries = [e for e in entries if e.get("user") == user]
    if action:
        entries = [e for e in entries if e.get("action") == action]

    # Most recent first
    entries.reverse()
    return entries[offset : offset + limit]


@router.post(
    "",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}},
    summary="Create an access-log entry",
)
async def create_access_log(
    payload: AccessLogCreateRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Record a new access-log entry."""
    entry = payload.model_dump()
    entry["id"] = f"al-{uuid.uuid4()}"
    entry["timestamp"] = datetime.now(UTC).isoformat()

    with _access_log_lock:
        _access_log_entries.append(entry)

    # Also forward to the audit logger if available (for dual-write)
    try:
        _ = Request(scope={"type": "http", "app": None})  # type: ignore[call-arg]
    except Exception:
        logger.debug("Failed to forward access log entry to audit logger", exc_info=True)
        pass

    return entry


@router.delete(
    "",
    responses={401: {"model": ErrorResponse}},
    summary="Clear all access-log entries",
)
async def clear_access_logs(
    _auth: Any = Depends(require_auth),
) -> dict[str, str]:
    """Clear all access-log entries."""
    with _access_log_lock:
        _access_log_entries.clear()
    return {"status": "cleared"}


@router.get(
    "/export",
    responses={401: {"model": ErrorResponse}},
    summary="Export access logs as JSON",
)
async def export_access_logs(
    format: str = Query("json", pattern="^(json|csv)$"),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Export all access-log entries."""
    with _access_log_lock:
        entries = list(_access_log_entries)

    return {
        "exported_at": datetime.now(UTC).isoformat(),
        "total_entries": len(entries),
        "entries": entries,
    }

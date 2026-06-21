"""Assignment store REST endpoints for collaborative triage."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from src.dashboard.fastapi.dependencies import require_auth
from src.learning.collaboration import AssignmentConflict, AssignmentStore

router = APIRouter(prefix="/api/assignments", tags=["Assignments"])
logger = logging.getLogger(__name__)


class AssignRequest(BaseModel):
    finding_id: str
    assigned_to: str
    assigned_by: str = ""
    notes: str = ""


def _get_store(request: Request) -> AssignmentStore:
    store = getattr(request.app.state, "assignment_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Assignment store not initialized")
    assert isinstance(store, AssignmentStore)
    return store


@router.get("/{finding_id}")
async def get_assignment(
    finding_id: str,
    _auth: Any = Depends(require_auth),
    store: AssignmentStore = Depends(_get_store),
) -> dict[str, Any] | None:
    assignment = store.get(finding_id)
    if assignment is None:
        return None
    return assignment.to_db_row()


@router.post("")
async def assign_finding(
    payload: AssignRequest,
    _auth: Any = Depends(require_auth),
    store: AssignmentStore = Depends(_get_store),
) -> dict[str, Any]:
    assignment = store.assign(
        finding_id=payload.finding_id,
        assigned_to=payload.assigned_to,
        assigned_by=payload.assigned_by,
        notes=payload.notes,
    )
    return assignment.to_db_row()


@router.post("/{finding_id}/lock")
async def lock_finding(
    finding_id: str,
    user_id: str = "anonymous",
    _auth: Any = Depends(require_auth),
    store: AssignmentStore = Depends(_get_store),
) -> dict[str, Any]:
    try:
        assignment = store.lock(finding_id, user_id)
    except AssignmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return assignment.to_db_row()


@router.post("/{finding_id}/unlock")
async def unlock_finding(
    finding_id: str,
    user_id: str = "anonymous",
    _auth: Any = Depends(require_auth),
    store: AssignmentStore = Depends(_get_store),
) -> dict[str, Any]:
    released = store.unlock(finding_id, user_id)
    return {"released": released}

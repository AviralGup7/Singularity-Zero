"""Notes CRUD endpoints for the FastAPI dashboard."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import (
    check_rate_limit,
    get_queue_client,
    require_admin,
    require_auth,
)
from src.dashboard.fastapi.schemas import (
    ErrorResponse,
    NoteCreateRequest,
    NoteDeleteResponse,
    NoteListResponse,
    NoteResponse,
    NoteUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notes", tags=["Notes"])


def _validate_target_name(name: str) -> bool:
    from src.dashboard.fastapi.validation import validate_target_name

    return validate_target_name(name)


@router.get(
    "/{target_name}",
    response_model=NoteListResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get notes for a target",
)
async def get_notes(
    target_name: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> NoteListResponse:
    """Return all notes for a target."""
    from src.pipeline.analyst_notes import get_all_notes

    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    notes = get_all_notes(target_name, output_dir=output_root)
    return NoteListResponse(
        notes=[NoteResponse(**n.model_dump()) for n in notes],
        target=target_name,
        count=len(notes),
    )


@router.post(
    "/{target_name}",
    response_model=NoteResponse,
    status_code=201,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Create a new note",
)
async def create_note(
    target_name: str,
    request: NoteCreateRequest,
    _auth: Any = Depends(require_auth),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> NoteResponse:
    """Create a new analyst note for a target."""
    from src.pipeline.analyst_notes import create_note as create_note_fn

    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    new_note = create_note_fn(
        target_name,
        request.finding_id,
        request.note,
        tags=request.tags,
        author=request.author,
        graph_node_id=request.graph_node_id,
        graph_edge_id=request.graph_edge_id,
        exchange_id=request.exchange_id,
        output_dir=output_root,
    )
    return NoteResponse(**new_note.model_dump())


@router.put(
    "/{target_name}/{note_id}",
    response_model=NoteResponse,
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
    },
    summary="Update a note",
)
async def update_note(
    target_name: str,
    note_id: str,
    request: NoteUpdateRequest,
    _auth: Any = Depends(require_auth),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> NoteResponse:
    """Update an existing note."""
    from src.pipeline.analyst_notes import update_note as update_note_fn

    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    updated = update_note_fn(
        target_name,
        request.finding_id,
        note_id,
        note=request.note,
        tags=request.tags,
        graph_node_id=request.graph_node_id,
        graph_edge_id=request.graph_edge_id,
        exchange_id=request.exchange_id,
        output_dir=output_root,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Note not found")
    return NoteResponse(**updated.model_dump())


@router.delete(
    "/{target_name}/{note_id}",
    response_model=NoteDeleteResponse,
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
    },
    summary="Delete a note",
)
async def delete_note(
    target_name: str,
    note_id: str,
    finding_id: str,
    _auth: Any = Depends(require_admin),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> NoteDeleteResponse:
    """Delete a note."""
    from src.pipeline.analyst_notes import delete_note as delete_note_fn

    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    success = delete_note_fn(target_name, finding_id, note_id, output_dir=output_root)
    if not success:
        raise HTTPException(status_code=404, detail="Note not found")

    return NoteDeleteResponse(deleted=True, note_id=note_id)

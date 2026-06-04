"""Import endpoints for the FastAPI dashboard (semgrep ingestion)."""

import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from src.dashboard.fastapi.dependencies import get_queue_client, require_admin
from src.dashboard.fastapi.routers.utils import get_safe_target_path
from src.dashboard.fastapi.schemas import ErrorResponse
from src.dashboard.fastapi.validation import (
    validate_json_payload,
    validate_run_name,
)

router = APIRouter(prefix="/api/imports", tags=["Imports"])


# ...
@router.post(
    "/semgrep",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
    },
    summary="Import Semgrep JSON for a target",
)
async def import_semgrep(
    target_name: str = Query(..., description="Target name for the imported results"),
    run: str | None = Query(None, description="Optional run name (will be created if omitted)"),
    file: UploadFile | None = File(None, description="Semgrep JSON file (multipart/form-data)"),
    overwrite: bool = Query(False, description="Overwrite existing semgrep.json if present"),
    _auth: Any = Depends(require_admin),
    services: Any = Depends(get_queue_client),
) -> dict[str, str]:
    output_root = services.query.output_root
    target_dir = get_safe_target_path(output_root, target_name)

    if not target_dir.exists():
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to create target directory: {exc}")

    if run:
        if not validate_run_name(run):
            raise HTTPException(status_code=400, detail="Invalid run name")
        run_dir = target_dir / run
    else:
        run_name = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_dir = target_dir / run_name

    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create run directory: {exc}")

    dest = run_dir / "semgrep.json"
    if dest.exists() and not overwrite:
        raise HTTPException(status_code=409, detail="semgrep.json already exists for this run")

    if file is None:
        raise HTTPException(
            status_code=400,
            detail="No file uploaded; provide semgrep JSON as multipart file 'file'",
        )

    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {exc}")

    MAX_UPLOAD_BYTES = 10 * 1024 * 1024
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload too large; maximum is {MAX_UPLOAD_BYTES // 1024 // 1024} MB",
        )

    if file.content_type and file.content_type not in (
        "application/json",
        "application/octet-stream",
        "",
    ):
        raise HTTPException(
            status_code=415, detail=f"Unsupported content type: {file.content_type}"
        )

    try:
        parsed = validate_json_payload(content)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}")
    if parsed is None:
        raise HTTPException(status_code=400, detail="Invalid or oversized JSON payload")

    try:
        # Bug #30 fix: previously the just-validated JSON was re-serialised
        # with ``json.dumps(parsed)`` and re-written. That round-trip lost
        # the original key ordering, indentation, Unicode escapes, and
        # numeric precision, so a downstream diff would see a "changed"
        # file even when semantically identical, and it doubled the I/O
        # for large imports. Write the validated bytes verbatim after
        # ``validate_json_payload`` has already parsed them.
        dest.write_bytes(content)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save semgrep.json: {exc}")

    return {"status": "ok", "target": target_dir.name, "run": run_dir.name, "file": "semgrep.json"}

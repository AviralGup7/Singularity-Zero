"""Import endpoints for the FastAPI dashboard (semgrep ingestion)."""

import datetime
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from src.dashboard.fastapi.dependencies import get_queue_client, require_admin
from src.dashboard.fastapi.schemas import ErrorResponse
from src.dashboard.fastapi.validation import (
    validate_json_payload,
    validate_run_name,
    validate_target_name,
)

router = APIRouter(prefix="/api/imports", tags=["Imports"])


def _find_target_dir(output_root: Path, target_id: str) -> Path | None:
    target = output_root / target_id
    if target.is_dir():
        return target
    for entry in output_root.iterdir():
        if entry.is_dir() and entry.name.lower() == target_id.lower():
            return entry
    return None


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
    if not validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    target_dir = _find_target_dir(output_root, target_name)
    if target_dir is None:
        target_dir = output_root / target_name
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

    parsed = validate_json_payload(content)
    if parsed is None:
        raise HTTPException(status_code=400, detail="Invalid or oversized JSON payload")

    try:
        dest.write_text(json.dumps(parsed), encoding="utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save semgrep.json: {exc}")

    return {"status": "ok", "target": target_dir.name, "run": run_dir.name, "file": "semgrep.json"}

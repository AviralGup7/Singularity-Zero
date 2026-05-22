"""Report library and compliance PDF endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.reporting.compliance_pdf import generate_compliance_pdf
from src.reporting.report_artifacts import build_report_library

router = APIRouter(prefix="/api/reports")


def _get_latest_run_dir(output_root: Path, target: str) -> Path | None:
    target_dir = output_root / target
    if not target_dir.is_dir():
        return None

    run_dirs = sorted(
        [
            entry
            for entry in target_dir.iterdir()
            if entry.is_dir() and (entry / "run_summary.json").exists()
        ],
        key=lambda d: d.name,
        reverse=True,
    )
    if not run_dirs:
        return None

    return run_dirs[0]


@router.get(
    "/library",
    summary="List signed report artefacts across pipeline runs",
)
async def list_report_library(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    return build_report_library(services.query.output_root)  # type: ignore[no-any-return]


@router.get(
    "/compliance/pdf",
    summary="Download SOC 2 / PCI-DSS compliance attestation PDF",
    response_class=FileResponse,
    responses={
        404: {"description": "No run artifacts found for the given target"},
        503: {"description": "reportlab is not installed"},
    },
)
async def get_compliance_pdf(
    target: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> FileResponse:
    """Return the compliance attestation PDF for the latest run of *target*."""
    output_root = services.query.output_root
    run_dir = _get_latest_run_dir(output_root, target)

    if run_dir is None:
        raise HTTPException(
            status_code=404,
            detail=f"No run artifacts found for target '{target}'",
        )

    summary_path = run_dir / "run_summary.json"
    if not summary_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"run_summary.json not found for target '{target}'",
        )

    try:
        summary: dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse run_summary.json for target '{target}': {exc}",
        ) from exc

    pdf_path = generate_compliance_pdf(summary=summary, run_dir=run_dir)

    if pdf_path is None:
        raise HTTPException(
            status_code=503,
            detail="reportlab is not installed",
        )

    if not pdf_path.is_file():
        raise HTTPException(
            status_code=500,
            detail="Attestation PDF was not generated",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename="attestation.pdf",
    )

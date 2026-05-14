"""Export endpoints for the FastAPI dashboard."""

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/export", tags=["Export"])


def _find_target_dir(output_root: Path, target_id: str) -> Path | None:
    target = output_root / target_id
    if target.is_dir() and (target / "index.html").exists():
        return target
    for entry in output_root.iterdir():
        if entry.is_dir() and entry.name.lower() == target_id.lower():
            return entry
    return None


def _find_latest_run_dir(target_dir: Path) -> Path | None:
    run_dirs = [
        child
        for child in target_dir.iterdir()
        if child.is_dir() and (child / "run_summary.json").exists()
    ]
    if not run_dirs:
        return None
    return max(run_dirs, key=lambda d: d.name)


def _load_findings(run_dir: Path) -> list[dict[str, Any]]:
    findings_path = run_dir / "findings.json"
    if not findings_path.exists():
        return []
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _load_all_findings(target_dir: Path) -> list[dict[str, Any]]:
    all_findings: list[dict[str, Any]] = []
    run_dirs = sorted(
        child
        for child in target_dir.iterdir()
        if child.is_dir() and (child / "run_summary.json").exists()
    )
    for run_dir in run_dirs:
        findings = _load_findings(run_dir)
        for f in findings:
            if isinstance(f, dict):
                f.setdefault("timestamp", run_dir.name)
                all_findings.append(f)
    return all_findings


@router.get(
    "/findings/all",
    responses={401: {"model": ErrorResponse}},
    summary="Export findings from all targets",
)
async def export_all_findings(
    format: str = Query("json", pattern="^(csv|json)$", description="Export format: csv or json"),
    max_targets: int = Query(50, ge=1, le=200, description="Maximum number of targets to export"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> Response:
    """Export findings from all targets in CSV or JSON format."""
    from src.reporting.export_findings import export_findings_csv, export_findings_json

    output_root = services.query.output_root
    all_findings: list[dict[str, Any]] = []
    target_count = 0

    for entry in sorted(output_root.iterdir(), key=lambda item: item.name.lower()):
        if not entry.is_dir() or entry.name.startswith("_"):
            continue
        if target_count >= max_targets:
            logger.warning("Export limited to %d targets; extra targets were skipped", max_targets)
            break
        target_count += 1
        findings = _load_all_findings(entry)
        for f in findings:
            if isinstance(f, dict):
                f.setdefault("target", entry.name)
                all_findings.append(f)

    if format == "csv":
        content = export_findings_csv(all_findings)
        return Response(
            content=content.encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="all_findings.csv"'},
        )
    content = export_findings_json(all_findings)
    return Response(
        content=content.encode("utf-8"),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="all_findings.json"'},
    )


@router.get(
    "/findings/{target_name}",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Export findings for a target",
)
async def export_findings(
    target_name: str,
    format: str = Query("json", pattern="^(csv|json)$", description="Export format: csv or json"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> Response:
    """Export all findings for a target in CSV or JSON format."""
    from src.reporting.export_findings import export_findings_csv, export_findings_json

    output_root = services.query.output_root
    target_dir = _find_target_dir(output_root, target_name)
    if target_dir is None:
        raise HTTPException(status_code=404, detail="Target not found")

    findings = _load_all_findings(target_dir)

    if format == "csv":
        content = export_findings_csv(findings)
        return Response(
            content=content.encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{target_dir.name}_findings.csv"'
            },
        )
    content = export_findings_json(findings)
    return Response(
        content=content.encode("utf-8"),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{target_dir.name}_findings.json"'
        },
    )


@router.get(
    "/findings/{target_name}/latest",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Export latest findings for a target",
)
async def export_latest_findings(
    target_name: str,
    format: str = Query("json", pattern="^(csv|json)$", description="Export format: csv or json"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> Response:
    """Export findings from the latest run for a target."""
    from src.reporting.export_findings import export_findings_csv, export_findings_json

    output_root = services.query.output_root
    target_dir = _find_target_dir(output_root, target_name)
    if target_dir is None:
        raise HTTPException(status_code=404, detail="Target not found")

    latest_run = _find_latest_run_dir(target_dir)
    findings = _load_findings(latest_run) if latest_run else []

    suffix = "_findings_latest"
    if format == "csv":
        content = export_findings_csv(findings)
        return Response(
            content=content.encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{target_dir.name}{suffix}.csv"'
            },
        )
    else:
        content = export_findings_json(findings)
        return Response(
            content=content.encode("utf-8"),
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{target_dir.name}{suffix}.json"'
            },
        )

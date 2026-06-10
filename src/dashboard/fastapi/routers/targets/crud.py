"""CRUD endpoints for target management."""

import json
import logging
import shutil
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.dashboard.fastapi.dependencies import get_queue_client, require_admin, require_auth
from src.dashboard.fastapi.routers.targets.validation import (
    TargetFindingsResponse,
    _normalize_finding_payload,
    is_target_owned_by_tenant,
)
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import (
    ErrorResponse,
    TargetInfo,
    TargetListResponse,
    TimelineEntry,
    TimelineResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/targets", tags=["Targets CRUD"])


@router.get(
    "",
    response_model=TargetListResponse,
    responses={401: {"model": ErrorResponse}},
    summary="List all targets",
)
async def list_targets(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> TargetListResponse:
    tenant_id = (_auth or {}).get("tenant_id", "default")
    targets = services.list_targets()
    filtered = [
        TargetInfo(**t) for t in targets if is_target_owned_by_tenant(t.get("name", ""), tenant_id)
    ]
    return TargetListResponse(
        targets=filtered,
        total=len(filtered),
    )


@router.delete(
    "/{target_name}",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Delete a target",
)
async def delete_target(
    target_name: str,
    request: Request,
    _auth: Any = Depends(require_admin),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Delete a target output directory. (SEC-FIX)"""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    user_id = (_auth or {}).get("user", "unknown")
    from src.dashboard.fastapi.routers.targets.validation import verify_tenant_boundary

    verify_tenant_boundary(request, target_name, tenant_id, user_id)

    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target_name)

    if not target_dir.is_dir() or target_dir.name.startswith("_"):
        raise HTTPException(status_code=400, detail="Target cannot be deleted")

    shutil.rmtree(target_dir)
    logger.info("Deleted target output directory: %s", target_dir)
    return {"deleted": True, "target": target_dir.name}


@router.get(
    "/{target_name}/findings",
    response_model=TargetFindingsResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get findings for a target",
)
async def get_target_findings(
    target_name: str,
    request: Request,
    run: str | None = Query(None, description="Specific run name"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> TargetFindingsResponse:
    """Retrieve findings for a specific target with traversal protection. (SEC-FIX)"""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    user_id = (_auth or {}).get("user", "unknown")
    from src.dashboard.fastapi.routers.targets.validation import verify_tenant_boundary

    verify_tenant_boundary(request, target_name, tenant_id, user_id)

    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target_name)

    if run:
        from pathlib import Path

        safe_run = Path(run).name
        run_dir = target_dir / safe_run
        if not run_dir.exists():
            raise HTTPException(status_code=404, detail="Run not found")
        run_dirs = [run_dir]
    else:
        run_dirs = sorted(
            child
            for child in target_dir.iterdir()
            if child.is_dir() and (child / "run_summary.json").exists()
        )

    all_findings = []
    for run_dir in run_dirs:
        findings_path = run_dir / "findings.json"
        if findings_path.exists():
            try:
                data = json.loads(findings_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for f in data:
                        if isinstance(f, dict):
                            f.setdefault("timestamp", run_dir.name)
                            all_findings.append(f)
            except Exception:
                logger.warning("Failed to parse findings.json at %s", findings_path, exc_info=True)

    return TargetFindingsResponse(
        findings=all_findings,
        total=len(all_findings),
        target=target_name,
    )


@router.get(
    "/{target_name}/timeline",
    response_model=TimelineResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get timeline data for a target",
)
async def get_timeline(
    target_name: str,
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> TimelineResponse:
    """Retrieve timeline with traversal protection. (SEC-FIX)"""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    user_id = (_auth or {}).get("user", "unknown")
    from src.dashboard.fastapi.routers.targets.validation import verify_tenant_boundary

    verify_tenant_boundary(request, target_name, tenant_id, user_id)

    output_root = services.query.output_root
    get_safe_target_dir(output_root, target_name)

    timeline = services.query.get_timeline_data(target_name)
    return TimelineResponse(
        target=target_name,
        timeline=[TimelineEntry(**entry) for entry in timeline],
        count=len(timeline),
    )


@router.get(
    "/{target_name}/compliance",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get compliance report for a target",
)
async def get_target_compliance(
    target_name: str,
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Get the latest compliance report with traversal protection. (SEC-FIX)"""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    user_id = (_auth or {}).get("user", "unknown")
    from src.dashboard.fastapi.routers.targets.validation import verify_tenant_boundary

    verify_tenant_boundary(request, target_name, tenant_id, user_id)

    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target_name)

    latest_run = max(
        (
            child
            for child in target_dir.iterdir()
            if child.is_dir() and (child / "run_summary.json").exists()
        ),
        key=lambda d: d.name,
        default=None,
    )
    if not latest_run:
        raise HTTPException(status_code=404, detail="No scan runs found for target")

    compliance_path = latest_run / "compliance_coverage.json"
    if compliance_path.exists():
        try:
            return cast(dict[str, Any], json.loads(compliance_path.read_text(encoding="utf-8")))
        except Exception as e:
            logger.error("Failed to load compliance report: %s", e)

    from src.reporting.compliance_mapping import build_compliance_report

    findings_path = latest_run / "findings.json"
    findings = []
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("Failed to parse findings.json at %s", findings_path, exc_info=True)

    return build_compliance_report(findings)


@router.get(
    "/findings/list",
    responses={401: {"model": ErrorResponse}},
    summary="List all findings with pagination",
)
async def list_all_findings(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Items per page"),
    severity: str | None = Query(None, description="Filter by severity"),
    target: str | None = Query(None, description="Filter by target name"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """List all findings with traversal protection on target filter. (SEC-FIX)"""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    if target and not is_target_owned_by_tenant(target, tenant_id):
        raise HTTPException(status_code=403, detail="Access denied to this target")

    output_root = services.query.output_root
    all_findings: list[dict[str, Any]] = []

    for entry in sorted(output_root.iterdir(), key=lambda item: item.name.lower()):
        if not entry.is_dir() or entry.name.startswith("_"):
            continue
        if not is_target_owned_by_tenant(entry.name, tenant_id):
            continue
        if target and entry.name.lower() != target.lower():
            continue

        run_dirs = sorted(
            child
            for child in entry.iterdir()
            if child.is_dir() and (child / "run_summary.json").exists()
        )
        for run_dir in run_dirs:
            summary_path = run_dir / "run_summary.json"
            findings_path = run_dir / "findings.json"

            summary_data: dict[str, Any] = {}
            if summary_path.exists():
                try:
                    parsed_summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    if isinstance(parsed_summary, dict):
                        summary_data = parsed_summary
                except Exception:
                    logger.warning("Failed to parse run_summary.json at %s", summary_path, exc_info=True)
                    summary_data = {}

            run_generated_at = str(
                summary_data.get("generated_at_utc")
                or summary_data.get("generated_at_ist")
                or run_dir.name
            ).strip()

            run_findings: list[dict[str, Any]] = []
            try:
                if findings_path.exists():
                    data = json.loads(findings_path.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        run_findings = [item for item in data if isinstance(item, dict)]
            except Exception:
                logger.warning("Failed to parse findings.json at %s", findings_path, exc_info=True)
                run_findings = []

            if not run_findings:
                top_actionable = summary_data.get("top_actionable_findings", [])
                if isinstance(top_actionable, list):
                    run_findings = [item for item in top_actionable if isinstance(item, dict)]

            for idx, finding in enumerate(run_findings, start=1):
                normalized = _normalize_finding_payload(
                    finding,
                    target_name=entry.name,
                    run_name=run_dir.name,
                    index=idx,
                    generated_at=run_generated_at,
                )
                if severity and str(normalized.get("severity", "")).lower() != severity.lower():
                    continue
                all_findings.append(normalized)

    all_findings.sort(key=lambda finding: str(finding.get("timestamp", "")), reverse=True)

    total = len(all_findings)
    start = (page - 1) * page_size
    end = start + page_size
    page_findings = all_findings[start:end]

    return {
        "findings": page_findings,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": end < total,
        "has_prev": page > 1,
    }

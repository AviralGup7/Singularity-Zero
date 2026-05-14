"""Target management endpoints for the FastAPI dashboard."""

import json
import logging
import shutil
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import get_cache_manager, get_queue_client, require_admin, require_auth
from src.dashboard.fastapi.schemas import (
    ErrorResponse,
    HistoricalScoreResponse,
    RiskScoreResponse,
    TargetInfo,
    TargetListResponse,
    TimelineEntry,
    TimelineResponse,
)

logger = logging.getLogger(__name__)


class TargetFindingsResponse(BaseModel):
    """Findings for a specific target."""

    findings: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    target: str = ""


router = APIRouter(prefix="/api/targets")


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
        "logic_diff": finding.get("metadata", {}).get("diff") if "logic_breach" in finding_type.lower() else None,
    }
    return normalized


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
    targets = services.list_targets()
    return TargetListResponse(
        targets=[TargetInfo(**t) for t in targets],
        total=len(targets),
    )


@router.delete(
    "/{target_name}",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Delete a target",
)
async def delete_target(
    target_name: str,
    _auth: Any = Depends(require_admin),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Delete a target output directory."""
    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root.resolve()
    target_dir = (output_root / target_name).resolve()
    if not target_dir.exists():
        target_dir = next(
            (
                child.resolve()
                for child in output_root.iterdir()
                if child.is_dir() and child.name.lower() == target_name.lower()
            ),
            None,
        )

    if target_dir is None or not target_dir.exists() or not target_dir.is_relative_to(output_root):
        raise HTTPException(status_code=404, detail="Target not found")
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
    run: str | None = Query(None, description="Specific run name"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> TargetFindingsResponse:
    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    target_dir = output_root / target_name
    if not target_dir.exists():
        target_dir = next(
            (
                child
                for child in output_root.iterdir()
                if child.is_dir() and child.name.lower() == target_name.lower()
            ),
            None,
        )
    if not target_dir or not target_dir.exists():
        raise HTTPException(status_code=404, detail="Target not found")

    if run:
        run_dir = target_dir / run
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
                pass  # Loading findings from single target failed, skip

    return TargetFindingsResponse(
        findings=all_findings,
        total=len(all_findings),
        target=target_name,
    )


@router.get(
    "/{target_name}/risk-score",
    response_model=RiskScoreResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get risk score for a target",
)
async def get_risk_score(
    target_name: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> RiskScoreResponse:
    from src.recon.scoring import compute_aggregate_risk_score

    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    target_dir = output_root / target_name
    if not target_dir.exists():
        raise HTTPException(status_code=404, detail="Target not found")

    latest_run = max(
        (
            child.name
            for child in target_dir.iterdir()
            if child.is_dir() and (child / "run_summary.json").exists()
        ),
        default="",
    )
    if not latest_run:
        raise HTTPException(status_code=404, detail="No runs found for target")

    findings_path = target_dir / latest_run / "findings.json"
    summary_path = target_dir / latest_run / "run_summary.json"

    findings: list[dict] = []
    run_summary: dict = {}

    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if not isinstance(findings, list):
                findings = []
        except Exception:
            pass

    if summary_path.exists():
        try:
            run_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    risk_data = compute_aggregate_risk_score(findings, run_summary)
    return RiskScoreResponse(
        target=target_name,
        aggregate_score=risk_data.get("aggregate_score", 0.0),
        severity=risk_data.get("severity", "info"),
        total_findings=risk_data.get("total_findings", 0),
        severity_breakdown=risk_data.get("severity_breakdown", {}),
        timestamp=risk_data.get("timestamp", ""),
    )


@router.get(
    "/{target_name}/timeline",
    response_model=TimelineResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get timeline data for a target",
)
async def get_timeline(
    target_name: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> TimelineResponse:
    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    timeline = services.query.get_timeline_data(target_name)
    return TimelineResponse(
        target=target_name,
        timeline=[TimelineEntry(**entry) for entry in timeline],
        count=len(timeline),
    )


@router.get(
    "/{target_name}/historical-scores",
    response_model=HistoricalScoreResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get historical scores for a target",
)
async def get_historical_scores(
    target_name: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
    cache_manager: Any = Depends(get_cache_manager),
) -> HistoricalScoreResponse:
    from src.recon.scoring import compute_historical_score

    if not _validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    target_dir = output_root / target_name
    if not target_dir.exists():
        raise HTTPException(status_code=404, detail="Target not found")

    run_dirs = sorted(
        (
            child
            for child in target_dir.iterdir()
            if child.is_dir() and (child / "findings.json").exists()
        ),
        key=lambda d: d.name,
    )

    endpoint_history: dict[str, list[dict]] = {}
    endpoint_current: dict[str, float] = {}

    for run_dir in run_dirs:
        findings_path = run_dir / "findings.json"
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not isinstance(findings, list):
            continue

        run_timestamp = run_dir.name
        summary_path = run_dir / "run_summary.json"
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                run_timestamp = summary.get("generated_at_utc", run_dir.name)
            except Exception:
                pass  # Loading findings from single target failed, skip

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            url = str(finding.get("url", "")).strip()
            if not url:
                continue
            score = float(finding.get("score", 0))
            endpoint_current[url] = score
            endpoint_history.setdefault(url, []).append(
                {
                    "score": score,
                    "severity": finding.get("severity", "info"),
                    "timestamp": run_timestamp,
                    "findings": [finding],
                }
            )

    result: dict[str, dict] = {}
    for endpoint, past_runs in endpoint_history.items():
        current = endpoint_current.get(endpoint, 0)
        result[endpoint] = compute_historical_score(
            endpoint, current, past_runs[:-1] if len(past_runs) > 1 else []
        )

    cache_manager.save_historical_scores(target_name, result)

    return HistoricalScoreResponse(
        target=target_name,
        endpoints=result,
        runs_analyzed=len(run_dirs),
    )


@router.get(
    "/findings/list",
    responses={401: {"model": ErrorResponse}},
    summary="List all findings with pagination",
)
async def list_all_findings(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    severity: str | None = Query(None, description="Filter by severity"),
    target: str | None = Query(None, description="Filter by target name"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """List all findings across all targets with pagination support."""
    output_root = services.query.output_root
    all_findings: list[dict[str, Any]] = []

    for entry in sorted(output_root.iterdir(), key=lambda item: item.name.lower()):
        if not entry.is_dir() or entry.name.startswith("_"):
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

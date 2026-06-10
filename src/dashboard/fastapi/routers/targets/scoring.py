"""Scoring-related endpoints for targets."""

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.dashboard.fastapi.dependencies import get_cache_manager, get_queue_client, require_auth
from src.dashboard.fastapi.routers.targets.validation import is_target_owned_by_tenant
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import (
    ErrorResponse,
    HistoricalScoreResponse,
    RiskScoreResponse,
    TargetComparisonResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/targets", tags=["Targets Scoring"])


@router.get(
    "/{target_name}/risk-score",
    response_model=RiskScoreResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get risk score for a target",
)
async def get_risk_score(
    target_name: str,
    request: Request,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> RiskScoreResponse:
    """Get risk score with traversal protection. (SEC-FIX)"""
    from src.recon.scoring import compute_aggregate_risk_score

    tenant_id = (_auth or {}).get("tenant_id", "default")
    user_id = (_auth or {}).get("user", "unknown")
    from src.dashboard.fastapi.routers.targets.validation import verify_tenant_boundary

    verify_tenant_boundary(request, target_name, tenant_id, user_id)

    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target_name)

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
    """Get historical scores with traversal protection. (SEC-FIX)"""
    from src.recon.scoring import compute_historical_score

    tenant_id = (_auth or {}).get("tenant_id", "default")
    if not is_target_owned_by_tenant(target_name, tenant_id):
        raise HTTPException(status_code=403, detail="Access denied to this target")

    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target_name)

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
                pass

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


def _get_target_comparison_details(target_name: str, services: Any) -> dict[str, Any]:
    """Retrieve comparison details with traversal protection. (SEC-FIX)"""
    output_root = services.query.output_root

    try:
        target_dir = get_safe_target_dir(output_root, target_name)
    except HTTPException:
        return {
            "name": target_name,
            "risk_score": 0.0,
            "finding_count": 0,
            "url_count": 0,
            "parameter_count": 0,
            "attack_chain_count": 0,
            "run_count": 0,
            "latest_run": "",
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    details = {
        "name": target_dir.name,
        "risk_score": 0.0,
        "finding_count": 0,
        "url_count": 0,
        "parameter_count": 0,
        "attack_chain_count": 0,
        "run_count": 0,
        "latest_run": "",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }

    run_dirs = sorted(
        [d for d in target_dir.iterdir() if d.is_dir() and (d / "run_summary.json").exists()],
        key=lambda x: x.name,
        reverse=True,
    )

    details["run_count"] = len(run_dirs)
    if not run_dirs:
        return details

    latest_run_dir = run_dirs[0]
    details["latest_run"] = latest_run_dir.name

    summary_path = latest_run_dir / "run_summary.json"
    findings_path = latest_run_dir / "findings.json"

    findings = []
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if not isinstance(findings, list):
                findings = []
        except Exception as e:
            logger.warning("Failed to load findings for target comparison: %s", e)

    summary = {}
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to load summary for target comparison: %s", e)

    from src.recon.scoring import compute_aggregate_risk_score

    risk_data = compute_aggregate_risk_score(findings, summary)
    details["risk_score"] = risk_data.get("aggregate_score", 0.0)

    details["finding_count"] = len(findings)
    counts = summary.get("counts", {})
    details["url_count"] = counts.get("urls", 0)
    details["parameter_count"] = counts.get("parameters", 0)

    attack_graph = summary.get("attack_graph", {})
    chains = attack_graph.get("chains", []) if isinstance(attack_graph, dict) else []
    details["attack_chain_count"] = len(chains)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if isinstance(f, dict):
            sev = str(f.get("severity", "info")).strip().lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            else:
                sev_counts["info"] += 1
    details["severity_counts"] = sev_counts

    return details


@router.get(
    "/compare",
    response_model=TargetComparisonResponse,
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Compare two targets side by side",
)
async def compare_targets(
    target_a: str = Query(..., description="First target name"),
    target_b: str = Query(..., description="Second target name"),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> TargetComparisonResponse:
    """Compare targets with traversal protection. (SEC-FIX)"""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    if not is_target_owned_by_tenant(target_a, tenant_id) or not is_target_owned_by_tenant(
        target_b, tenant_id
    ):
        raise HTTPException(status_code=403, detail="Access denied to one or both targets")

    res_a = _get_target_comparison_details(target_a, services)
    res_b = _get_target_comparison_details(target_b, services)

    return TargetComparisonResponse(
        target_a=res_a,
        target_b=res_b,
    )

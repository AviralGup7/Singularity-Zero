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


@router.get(
    "/sla/trending",
    summary="Get GRC SLA trending telemetry and active breaches",
)
async def get_sla_trending(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Retrieve MTTR and active SLA breach trends for all tenant-scoped targets."""
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
    from src.reporting.sla_tracker import SLATracker

    tenant_id = (_auth or {}).get("tenant_id", "default")
    output_root = services.query.output_root

    total_findings = 0
    total_remediated = 0
    total_open = 0
    active_breaches = 0
    mttr_durations = []
    
    # Trend grouping by month: e.g. {"2026-05": {"remediated": 0, "breached": 0, "total": 0}}
    trend_data: dict[str, dict[str, Any]] = {}

    for target_dir in output_root.iterdir():
        if not target_dir.is_dir():
            continue
        if not is_target_owned_by_tenant(target_dir.name, tenant_id):
            continue

        for run_dir in target_dir.iterdir():
            if not run_dir.is_dir() or run_dir.name == "checkpoints":
                continue
            findings_path = run_dir / "findings.json"
            if not findings_path.exists():
                continue

            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
            except Exception:
                continue

            if not isinstance(findings, list):
                continue

            sla_report = SLATracker.check_sla_compliance(findings)
            
            for f in findings:
                if not isinstance(f, dict):
                    continue
                total_findings += 1
                
                # Determine discovery and remediation timestamp
                disc_ts = f.get("discovered_at") or f.get("timestamp")
                if isinstance(disc_ts, str):
                    try:
                        import datetime
                        disc_ts = datetime.datetime.fromisoformat(disc_ts).timestamp()
                    except Exception:
                        disc_ts = time.time()
                disc_ts = float(disc_ts or time.time())

                # Group by month for trending
                import datetime
                dt = datetime.datetime.fromtimestamp(disc_ts, datetime.timezone.utc)
                month_key = dt.strftime("%Y-%m")
                trend_entry = trend_data.setdefault(month_key, {"remediated_count": 0, "breach_count": 0, "total_count": 0, "mttr_days": 0.0, "_mttr_list": []})
                trend_entry["total_count"] += 1

                status = str(f.get("status") or "").lower()
                is_remediated = status in {"remediated", "resolved", "verified"}
                
                if is_remediated:
                    total_remediated += 1
                    rem_ts = f.get("remediated_at") or f.get("resolved_at") or f.get("timestamp")
                    if isinstance(rem_ts, str):
                        try:
                            rem_ts = datetime.datetime.fromisoformat(rem_ts).timestamp()
                        except Exception:
                            rem_ts = time.time()
                    rem_ts = float(rem_ts or time.time())
                    
                    duration = max(0.0, rem_ts - disc_ts)
                    mttr_durations.append(duration)
                    trend_entry["remediated_count"] += 1
                    trend_entry["_mttr_list"].append(duration)
                else:
                    total_open += 1
                    # Check if currently breached
                    severity = str(f.get("severity", "info")).lower()
                    age = time.time() - disc_ts
                    sla_limit = SLATracker.SLA_MEDIUM_SECONDS
                    if severity == "critical":
                        sla_limit = SLATracker.SLA_CRITICAL_SECONDS
                    elif severity == "high":
                        sla_limit = SLATracker.SLA_HIGH_SECONDS
                        
                    if age > sla_limit:
                        active_breaches += 1
                        trend_entry["breach_count"] += 1

    # Post-process monthly trends
    sorted_trend = []
    for month in sorted(trend_data.keys()):
        entry = trend_data[month]
        mttrs = entry.pop("_mttr_list")
        entry["mttr_days"] = round((sum(mttrs) / len(mttrs)) / (24 * 3600), 2) if mttrs else 0.0
        sorted_trend.append({
            "month": month,
            "remediated_count": entry["remediated_count"],
            "breach_count": entry["breach_count"],
            "total_count": entry["total_count"],
            "mttr_days": entry["mttr_days"]
        })

    avg_mttr_days = round((sum(mttr_durations) / len(mttr_durations)) / (24 * 3600), 2) if mttr_durations else 0.0
    compliance_rate = round(((total_findings - active_breaches) / total_findings * 100), 1) if total_findings else 100.0

    return {
        "active_breaches": active_breaches,
        "mttr_days": avg_mttr_days,
        "total_findings": total_findings,
        "remediated_findings_count": total_remediated,
        "open_findings_count": total_open,
        "sla_compliance_rate": compliance_rate,
        "trending": sorted_trend,
    }


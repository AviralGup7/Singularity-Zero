"""Report library and compliance PDF endpoints."""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import ErrorResponse
from src.reporting.compliance_pdf import generate_compliance_pdf
from src.reporting.platform_clients import (
    AppleClient,
    AWSClient,
    BugcrowdClient,
    GoogleVRPClient,
    GovDefenseClient,
    HackerOneClient,
    IntigritiClient,
    MetaClient,
    MozillaClient,
    MSRCAgent,
    OpenBugBountyClient,
    SubmissionResult,
    SynackClient,
    YesWeHackClient,
)
from src.reporting.report_artifacts import build_report_library

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports")


from src.dashboard.fastapi.routers.utils import get_safe_target_dir


def _get_latest_run_dir_safe(output_root: Path, target_name: str) -> Path | None:
    target_dir = get_safe_target_dir(output_root, target_name)

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
    "/ai-summary",
    response_model=dict[str, Any],
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Get AI executive security posture summary for a target",
)
async def get_ai_executive_summary(
    target: str,
    auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    output_root = services.query.output_root
    tenant_id = (auth or {}).get("tenant_id", "default")

    # 1. Enforce strict multi-tenant boundary checks
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    if not is_target_owned_by_tenant(target, tenant_id):
        raise HTTPException(
            status_code=403, detail="Access denied to requested target infrastructure"
        )

    # 2. Get latest run directory
    run_dir = _get_latest_run_dir_safe(output_root, target)
    if not run_dir:
        raise HTTPException(status_code=404, detail="No completed scan runs found for target")

    # 3. Load findings
    _findings = []
    findings_path = run_dir / "findings.json"
    if findings_path.exists():
        try:
            _findings = json.loads(findings_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning(
                "Failed to parse findings.json for AI summary at %s", findings_path, exc_info=True
            )

    # 4. Load compliance report if available
    _compliance_report = None
    compliance_path = run_dir / "compliance_coverage.json"
    if compliance_path.exists():
        try:
            _compliance_report = json.loads(compliance_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning(
                "Failed to parse compliance_coverage.json at %s", compliance_path, exc_info=True
            )

    # 5. AI summary removed
    raise HTTPException(status_code=501, detail="AI executive summary module removed.")


@router.get(
    "/library",
    summary="List signed report artefacts across pipeline runs",
)
async def list_report_library(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    tenant_id = (_auth or {}).get("tenant_id", "default") if isinstance(_auth, dict) else "default"
    library = build_report_library(services.query.output_root)
    reports = [
        report
        for report in library.get("reports", [])
        if is_target_owned_by_tenant(str(report.get("target", "")), tenant_id)
    ]
    return {"reports": reports, "total": len(reports)}


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
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant

    tenant_id = (_auth or {}).get("tenant_id", "default") if isinstance(_auth, dict) else "default"
    if not is_target_owned_by_tenant(target, tenant_id):
        raise HTTPException(
            status_code=403, detail="Access denied to requested target infrastructure"
        )
    output_root = services.query.output_root
    run_dir = _get_latest_run_dir_safe(output_root, target)

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
        logger.error("Failed to parse run_summary.json for target '%s': %s", target, exc)
        raise HTTPException(
            status_code=500,
            detail=f"run_summary.json is corrupt for target '{target}'",
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
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}},
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
                logger.warning(
                    "Failed to parse findings.json for SLA trending at %s",
                    findings_path,
                    exc_info=True,
                )
                continue

            if not isinstance(findings, list):
                continue

            SLATracker.check_sla_compliance(findings)

            for f in findings:
                if not isinstance(f, dict):
                    continue
                total_findings += 1

                # Determine discovery and remediation timestamp
                disc_ts = f.get("discovered_at")
                if disc_ts is None:
                    disc_ts = f.get("timestamp")
                if isinstance(disc_ts, str):
                    try:
                        disc_ts = datetime.datetime.fromisoformat(disc_ts).timestamp()
                    except Exception:
                        disc_ts = None
                disc_ts = time.time() if disc_ts is None else float(disc_ts)

                # Group by month for trending
                # SECURITY: the loop variable is named ``report_dt`` to
                # avoid shadowing the imported ``datetime`` module.
                report_dt = datetime.datetime.fromtimestamp(disc_ts, datetime.UTC)
                month_key = report_dt.strftime("%Y-%m")
                trend_entry = trend_data.setdefault(
                    month_key,
                    {
                        "remediated_count": 0,
                        "breach_count": 0,
                        "total_count": 0,
                        "mttr_days": 0.0,
                        "_mttr_list": [],
                    },
                )
                trend_entry["total_count"] += 1

                status = str(f.get("status") or "").lower()
                is_remediated = status in {"remediated", "resolved", "verified"}

                if is_remediated:
                    total_remediated += 1
                    rem_ts = f.get("remediated_at")
                    if rem_ts is None:
                        rem_ts = f.get("resolved_at")
                    if rem_ts is None:
                        rem_ts = f.get("timestamp")
                    if isinstance(rem_ts, str):
                        try:
                            rem_ts = datetime.datetime.fromisoformat(rem_ts).timestamp()
                        except Exception:
                            rem_ts = None
                    rem_ts = time.time() if rem_ts is None else float(rem_ts)

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
        sorted_trend.append(
            {
                "month": month,
                "remediated_count": entry["remediated_count"],
                "breach_count": entry["breach_count"],
                "total_count": entry["total_count"],
                "mttr_days": entry["mttr_days"],
            }
        )

    avg_mttr_days = (
        round((sum(mttr_durations) / len(mttr_durations)) / (24 * 3600), 2)
        if mttr_durations
        else 0.0
    )
    compliance_rate = (
        round(((total_findings - active_breaches) / total_findings * 100), 1)
        if total_findings
        else 100.0
    )

    return {
        "active_breaches": active_breaches,
        "mttr_days": avg_mttr_days,
        "total_findings": total_findings,
        "remediated_findings_count": total_remediated,
        "open_findings_count": total_open,
        "sla_compliance_rate": compliance_rate,
        "trending": sorted_trend,
    }


# ---------------------------------------------------------------------------
# Platform submission endpoints (HackerOne / Bugcrowd / Intigriti / Synack / YesWeHack / etc.)
# ---------------------------------------------------------------------------


class SubmitFindingPayload(BaseModel):
    platform: str = Field(
        ...,
        pattern=r"^(hackerone|bugcrowd|intigriti|synack|yeswehack|openbugbounty|googlevrp|meta|apple|aws|msrc|mozilla|govdefense)$",
    )
    draft: bool = True
    additional_notes: str = ""


_PLATFORM_CLIENTS: dict[str, Any] = {}
_PLATFORM_INIT_ERRORS: dict[str, str] = {}

# Defect 4 fix: Per-finding submission lock and idempotency tracking.
# Prevents duplicate submissions from concurrent requests and rapid clicks.
_submission_locks: dict[str, threading.Lock] = {}
_submission_locks_guard = threading.Lock()
_submitted_findings: dict[str, str] = {}  # idempotency_key -> report_id


def _get_clients() -> dict[str, Any]:
    """Lazy-init the platform-client singleton (reads tokens from env)."""
    if not _PLATFORM_CLIENTS and not _PLATFORM_INIT_ERRORS:
        factories: dict[str, Any] = {
            "hackerone": HackerOneClient,
            "bugcrowd": BugcrowdClient,
            "intigriti": IntigritiClient,
            "synack": SynackClient,
            "yeswehack": YesWeHackClient,
            "openbugbounty": OpenBugBountyClient,
            "googlevrp": GoogleVRPClient,
            "meta": MetaClient,
            "apple": AppleClient,
            "aws": AWSClient,
            "msrc": MSRCAgent,
            "mozilla": MozillaClient,
            "govdefense": GovDefenseClient,
        }
        for platform, factory in factories.items():
            try:
                _PLATFORM_CLIENTS[platform] = factory()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("%s init failed: %s", factory.__name__, exc)
                _PLATFORM_INIT_ERRORS[platform] = str(exc)
                _PLATFORM_CLIENTS[platform] = None
    return _PLATFORM_CLIENTS


def _get_submission_lock(finding_id: str, platform: str) -> threading.Lock:
    """Return a per-finding+platform lock to serialize submissions.

    Defect 4 fix: Prevents concurrent duplicate submissions for the same
    finding to the same platform.
    """
    key = f"{finding_id}:{platform}"
    with _submission_locks_guard:
        if key not in _submission_locks:
            _submission_locks[key] = threading.Lock()
        return _submission_locks[key]


def _idempotency_key(finding_id: str, platform: str) -> str:
    """Compute a stable idempotency key for a finding+platform pair."""
    raw = f"{finding_id}:{platform}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@router.get(
    "/platforms",
    response_model=dict[str, Any],
    responses={401: {"model": ErrorResponse}},
    summary="List configured bug-bounty platform clients",
)
async def list_platforms(_auth: Any = Depends(require_auth)) -> dict[str, Any]:
    """Return a per-platform readiness summary."""
    clients = _get_clients()
    out: list[dict[str, Any]] = []
    platforms = (
        "hackerone",
        "bugcrowd",
        "intigriti",
        "synack",
        "yeswehack",
        "openbugbounty",
        "googlevrp",
        "meta",
        "apple",
        "aws",
        "msrc",
        "mozilla",
        "govdefense",
    )
    for platform in platforms:
        client = clients.get(platform)
        if client is None:
            out.append(
                {
                    "platform": platform,
                    "ready": False,
                    "configured": False,
                    "last_error": _PLATFORM_INIT_ERRORS.get(platform, "init_failed"),
                }
            )
            continue
        ready = bool(getattr(client, "ready", False))
        out.append(
            {
                "platform": platform,
                "ready": ready,
                "configured": ready,
                "last_error": None if ready else "missing_credentials",
            }
        )
    return {"clients": out}


def _mark_finding_reported_on_disk(findings_path: Path, finding_id: str, platform: str) -> None:
    """Atomically write already_reported flag to findings.json.

    Defect 4 fix: Uses temp-file + rename for atomic write to prevent
    corruption from concurrent writers.
    """
    findings_list = json.loads(findings_path.read_text(encoding="utf-8"))
    modified = False
    for f in findings_list:
        if isinstance(f, dict) and str(f.get("id")) == finding_id:
            reported = f.setdefault("already_reported_platforms", [])
            if platform not in reported:
                reported.append(platform)
            f["already_reported"] = True
            modified = True
            break
    if not modified:
        return
    tmp_fd, tmp_path = tempfile.mkstemp(dir=findings_path.parent, suffix=".tmp", prefix="findings_")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_f:
            json.dump(findings_list, tmp_f, indent=2)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        Path(tmp_path).replace(findings_path)
    except Exception:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _resolve_run_dir(services: Any, target: str, run_id: str) -> Path | None:
    output_root: Path = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target)
    candidate = (target_dir / run_id).resolve()
    if not candidate.is_dir():
        return None
    if target_dir.resolve() not in candidate.parents and candidate != target_dir:
        return None
    return candidate


@router.post(
    "/runs/{run_id}/findings/{finding_id}/submit",
    summary="Submit a finding to a bug-bounty platform",
)
async def submit_finding_to_platform(
    run_id: str,
    finding_id: str,
    payload: SubmitFindingPayload,
    auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Push a finding to one of the supported platforms."""
    target = (auth or {}).get("target")
    if not target:
        from src.dashboard.fastapi.routers.findings.crud import _locate_finding_on_disk

        tenant_id = (auth or {}).get("tenant_id", "default")
        located = _locate_finding_on_disk(services.query.output_root, finding_id, tenant_id)
        if not located:
            raise HTTPException(status_code=404, detail="Finding not found to resolve target name")
        target = located[0]
        from src.dashboard.fastapi.routers.targets.validation import is_target_owned_by_tenant

        if not is_target_owned_by_tenant(target, tenant_id):
            raise HTTPException(
                status_code=403, detail="Access denied to requested target infrastructure"
            )
    run_dir = _resolve_run_dir(services, target, run_id)
    if run_dir is None:
        raise HTTPException(status_code=404, detail="Run not found for current tenant")

    findings_path = run_dir / "findings.json"
    if not findings_path.is_file():
        raise HTTPException(status_code=404, detail="findings.json not present for this run")

    try:
        findings_list = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"findings.json is corrupt: {exc}") from exc

    if not isinstance(findings_list, list):
        raise HTTPException(status_code=500, detail="findings.json is malformed")

    finding: dict[str, Any] | None = next(
        (f for f in findings_list if isinstance(f, dict) and str(f.get("id")) == finding_id),
        None,
    )
    if finding is None:
        raise HTTPException(
            status_code=404,
            detail=f"Finding {finding_id!r} not found in run {run_id!r}",
        )

    if payload.additional_notes:
        finding = {**finding, "additional_notes": payload.additional_notes}
    finding = {**finding, "draft": payload.draft}

    client = _get_clients().get(payload.platform)
    if client is None or not getattr(client, "ready", False):
        raise HTTPException(
            status_code=503,
            detail=f"Platform client for {payload.platform!r} is not configured",
        )

    # Defect 4 fix: Idempotency check + per-finding serialization.
    idem_key = _idempotency_key(finding_id, payload.platform)
    sub_lock = _get_submission_lock(finding_id, payload.platform)
    with sub_lock:
        # Check if already submitted (idempotent return)
        if idem_key in _submitted_findings:
            existing_report_id = _submitted_findings[idem_key]
            return {
                "platform": payload.platform,
                "submitted": True,
                "report_id": existing_report_id or None,
                "url": None,
                "error": None,
                "status_code": None,
                "idempotent": True,
            }

        try:
            result: SubmissionResult = await client.submit(finding)
        except Exception:
            logger.exception("Platform submission failed")
            raise HTTPException(
                status_code=502,
                detail=f"Platform submission to {payload.platform!r} failed",
            )

    report_id = getattr(result, "external_id", "") or None

    # Defect 4 fix: Record submission idempotency key
    if bool(getattr(result, "ok", False)):
        _submitted_findings[idem_key] = report_id or ""

    # Defect 4 fix: Write back already_reported=true to findings.json atomically
    if bool(getattr(result, "ok", False)):
        try:
            _mark_finding_reported_on_disk(findings_path, finding_id, payload.platform)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to persist already_reported for finding %s: %s",
                finding_id,
                exc,
            )

    return {
        "platform": result.platform,
        "submitted": bool(getattr(result, "ok", False)),
        "report_id": report_id,
        "url": getattr(result, "url", "") or None,
        "error": getattr(result, "error", "") or None,
        "status_code": getattr(result, "status_code", 0) or None,
    }

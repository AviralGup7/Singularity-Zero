"""Findings management endpoints for the FastAPI dashboard."""

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_admin, require_auth
from src.dashboard.fastapi.routers.risk import _parse_timestamp, _stable_float
from src.dashboard.fastapi.routers.targets import _normalize_finding_payload
from src.dashboard.fastapi.schemas import ErrorResponse, FindingsSummaryResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


def _find_finding_by_id(output_root: Any, finding_id: str) -> dict[str, Any] | None:
    for target_entry in output_root.iterdir():
        if not target_entry.is_dir():
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir():
                continue
            findings_path = run_entry / "findings.json"
            if not findings_path.exists():
                continue
            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: S112
                continue
            if not isinstance(findings, list):
                continue
            for idx, finding in enumerate(findings, start=1):
                if not isinstance(finding, dict):
                    continue
                fid = (
                    finding.get("id")
                    or finding.get("finding_id")
                    or f"{target_entry.name}-{run_entry.name}-{idx}"
                )
                if str(fid) == finding_id:
                    return _normalize_finding_payload(
                        finding,
                        target_name=target_entry.name,
                        run_name=run_entry.name,
                        index=idx,
                    )
    return None


def _seeded_timeline_events(limit: int, offset: int) -> list[dict[str, Any]]:
    targets = ["api.example.com", "portal.example.com", "auth.example.com"]
    titles = [
        "Authentication boundary drift",
        "Verbose error disclosure",
        "Open redirect candidate",
        "Weak cache control on sensitive route",
        "GraphQL introspection signal",
        "High-value endpoint lacks rate limit",
    ]
    severities = ["critical", "high", "medium", "low"]
    today = datetime.now(UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    events: list[dict[str, Any]] = []
    for index in range(72):
        target = targets[index % len(targets)]
        timestamp = today - timedelta(hours=index * 5)
        severity = severities[int(_stable_float(f"timeline:{index}", 0, len(severities) - 0.01))]
        finding_id = f"seed-finding-{index + 1}"
        events.append(
            {
                "id": f"event-{finding_id}",
                "title": titles[index % len(titles)],
                "severity": severity,
                "target": target,
                "timestamp": timestamp.isoformat(),
                "finding_id": finding_id,
                "job_id": f"seed-job-{(index % 4) + 1}",
                "url": f"https://{target}/route/{index % 9}",
                "module": "seeded",
                "preview": "Seeded demonstrator event generated because no findings were available.",
                "confidence": round(_stable_float(f"timeline:{index}:confidence", 0.55, 0.96), 2),
            }
        )
    return events[offset : offset + limit]


def _collect_timeline_events(
    output_root: Any,
    *,
    job_id: str | None = None,
    job_target: str | None = None,
    severity: str | None = None,
    target: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    if not output_root.exists():
        return []

    start_dt = _parse_timestamp(start_date, "1970-01-01") if start_date else None
    end_dt = _parse_timestamp(end_date, "2999-12-31") if end_date else None
    events: list[dict[str, Any]] = []

    for target_entry in sorted(output_root.iterdir(), key=lambda path: path.name.lower()):
        if not target_entry.is_dir() or target_entry.name.startswith("_"):
            continue
        if target and target_entry.name.lower() != target.lower():
            continue
        if job_target and target_entry.name.lower() != job_target.lower():
            continue

        for run_entry in sorted(target_entry.iterdir(), key=lambda path: path.name):
            if not run_entry.is_dir():
                continue
            if job_id and run_entry.name != job_id and not job_target:
                continue

            findings_path = run_entry / "findings.json"
            summary_path = run_entry / "run_summary.json"
            findings_data = []
            if findings_path.exists():
                try:
                    parsed = json.loads(findings_path.read_text(encoding="utf-8"))
                    findings_data = parsed if isinstance(parsed, list) else []
                except (OSError, json.JSONDecodeError):
                    findings_data = []

            if not findings_data and summary_path.exists():
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    top_findings = (
                        summary.get("top_actionable_findings", [])
                        if isinstance(summary, dict)
                        else []
                    )
                    findings_data = top_findings if isinstance(top_findings, list) else []
                except (OSError, json.JSONDecodeError):
                    findings_data = []

            run_generated_at = run_entry.name
            if summary_path.exists():
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    if isinstance(summary, dict):
                        run_generated_at = str(
                            summary.get("generated_at_utc")
                            or summary.get("generated_at_ist")
                            or run_entry.name
                        )
                except (OSError, json.JSONDecodeError):
                    run_generated_at = run_entry.name

            for idx, finding in enumerate(findings_data, start=1):
                if not isinstance(finding, dict):
                    continue
                normalized = _normalize_finding_payload(
                    finding,
                    target_name=target_entry.name,
                    run_name=run_entry.name,
                    index=idx,
                    generated_at=run_generated_at,
                )
                event_severity = str(normalized.get("severity", "info")).lower()
                if severity and event_severity != severity.lower():
                    continue
                timestamp = _parse_timestamp(
                    normalized.get("timestamp") or normalized.get("date"),
                    run_generated_at,
                )
                if start_dt and timestamp < start_dt:
                    continue
                if end_dt and timestamp > end_dt:
                    continue
                finding_id = str(
                    normalized.get("id")
                    or normalized.get("finding_id")
                    or f"{target_entry.name}-{run_entry.name}-{idx}"
                )
                events.append(
                    {
                        "id": f"{run_entry.name}:{finding_id}",
                        "title": str(
                            normalized.get("title") or normalized.get("type") or "Finding"
                        ),
                        "severity": event_severity,
                        "target": target_entry.name,
                        "timestamp": timestamp.isoformat(),
                        "finding_id": finding_id,
                        "job_id": run_entry.name,
                        "url": str(normalized.get("url") or normalized.get("target") or ""),
                        "module": str(normalized.get("module") or normalized.get("type") or ""),
                        "preview": str(
                            normalized.get("description") or normalized.get("title") or ""
                        )[:240],
                        "confidence": normalized.get("confidence", 0),
                    }
                )

    events.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return events[offset : offset + limit]


def _telemetry_timeline_events(
    jobs: list[dict[str, Any]],
    *,
    job_id: str | None = None,
    severity: str | None = None,
    target: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict[str, Any]]:
    start_dt = _parse_timestamp(start_date, "1970-01-01") if start_date else None
    end_dt = _parse_timestamp(end_date, "2999-12-31") if end_date else None
    events: list[dict[str, Any]] = []
    for job in jobs:
        current_job_id = str(job.get("id") or "")
        if job_id and current_job_id != job_id:
            continue
        job_target = str(job.get("target_name") or job.get("hostname") or "")
        if target and job_target.lower() != target.lower():
            continue
        telemetry_events = job.get("telemetry_events")
        if not isinstance(telemetry_events, list):
            continue
        for telemetry in telemetry_events:
            if not isinstance(telemetry, dict):
                continue
            event_type = str(telemetry.get("event_type") or "")
            if event_type not in {"artifact.discovered", "finding.discovered"}:
                continue
            event_severity = str(telemetry.get("severity") or "info").lower() or "info"
            if severity and event_severity != severity.lower():
                continue
            timestamp = _parse_timestamp(telemetry.get("timestamp"), datetime.now(UTC).isoformat())
            if start_dt and timestamp < start_dt:
                continue
            if end_dt and timestamp > end_dt:
                continue
            artifact_type = str(telemetry.get("artifact_type") or "")
            artifact_id = str(telemetry.get("artifact_id") or "")
            finding_id = str(telemetry.get("finding_id") or telemetry.get("event_id") or "")
            title = str(telemetry.get("message") or event_type)
            events.append(
                {
                    "id": str(telemetry.get("event_id") or f"{current_job_id}:{len(events)}"),
                    "title": title,
                    "severity": event_severity,
                    "target": job_target,
                    "timestamp": timestamp.isoformat(),
                    "finding_id": finding_id or artifact_id,
                    "job_id": current_job_id,
                    "url": artifact_id
                    if artifact_type in {"url", "live_host", "subdomain"}
                    else str(telemetry.get("target") or ""),
                    "module": str(
                        telemetry.get("stage") or telemetry.get("check_id") or "telemetry"
                    ),
                    "preview": f"{event_type} from {telemetry.get('source', 'pipeline')}",
                    "confidence": (telemetry.get("payload") or {}).get("confidence")
                    if isinstance(telemetry.get("payload"), dict)
                    else None,
                    "telemetry_event": telemetry,
                }
            )
    return events


@router.get(
    "",
    response_model=FindingsSummaryResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get summary of all findings",
)
async def get_findings_summary(
    target: str | None = Query(None),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Return a global summary of findings across all targets."""
    output_root = services.query.output_root
    total_findings = 0
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_module: dict[str, int] = {}
    target_summaries: list[dict[str, Any]] = []
    targets_with_findings = 0
    total_targets = 0
    all_findings_list: list[dict[str, Any]] = []

    if not output_root.exists():
        return {
            "total_findings": 0,
            "severity_totals": severity_totals,
            "by_severity": severity_totals,
            "by_module": {},
            "findings": [],
            "targets": [],
            "targets_with_findings": 0,
            "total_targets": 0,
        }

    for entry in sorted(output_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith("_"):
            continue

        if target and entry.name.lower() != target.lower():
            continue

        total_targets += 1
        target_finding_count = 0
        target_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # Look for findings in all run directories
        run_dirs = [d for d in entry.iterdir() if d.is_dir() and (d / "run_summary.json").exists()]
        if not run_dirs:
            # Fallback to check all subdirs
            run_dirs = [d for d in entry.iterdir() if d.is_dir() and d.name != "checkpoints"]

        for run_dir in run_dirs:
            findings_path = run_dir / "findings.json"
            if findings_path.exists():
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    if isinstance(findings, list):
                        for f in findings:
                            sev = str(f.get("severity", "info")).lower()
                            if sev in severity_totals:
                                severity_totals[sev] += 1
                                target_severity_counts[sev] += 1

                            mod = str(f.get("module", "unknown"))
                            by_module[mod] = by_module.get(mod, 0) + 1

                            total_findings += 1
                            target_finding_count += 1

                            if len(all_findings_list) < 50:
                                all_findings_list.append(f)
                except Exception:  # noqa: S112
                    continue

        if target_finding_count > 0:
            targets_with_findings += 1
            target_summaries.append(
                {
                    "name": entry.name,
                    "finding_count": target_finding_count,
                    "severity_counts": target_severity_counts,
                }
            )

    return {
        "total_findings": total_findings,
        "severity_totals": severity_totals,
        "by_severity": severity_totals,
        "by_module": by_module,
        "findings": all_findings_list,
        "targets": target_summaries,
        "targets_with_findings": targets_with_findings,
        "total_targets": total_targets,
    }


@router.get(
    "/timeline",
    response_model=list[dict[str, Any]],
    responses={401: {"model": ErrorResponse}},
    summary="Get finding discovery events across jobs",
)
async def get_findings_timeline(
    job_id: str | None = Query(None, description="Filter by job or run identifier"),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info)$"),
    target: str | None = Query(None, description="Filter by target name"),
    start_date: str | None = Query(None, description="Inclusive ISO start date"),
    end_date: str | None = Query(None, description="Inclusive ISO end date"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> list[dict[str, Any]]:
    job_target = None
    if job_id:
        job = services.get_job(job_id)
        if job:
            job_target = str(job.get("target_name") or "").strip() or None

    events = _collect_timeline_events(
        services.query.output_root,
        job_id=job_id,
        job_target=job_target,
        severity=severity,
        target=target,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )
    telemetry_events = _telemetry_timeline_events(
        services.list_jobs(),
        job_id=job_id,
        severity=severity,
        target=target,
        start_date=start_date,
        end_date=end_date,
    )
    if telemetry_events:
        merged = {str(item.get("id")): item for item in [*events, *telemetry_events]}
        events = sorted(
            merged.values(), key=lambda item: str(item.get("timestamp", "")), reverse=True
        )[offset : offset + limit]
    if not events and offset == 0:
        return _seeded_timeline_events(limit, offset)
    return events


@router.get(
    "/{finding_id}/remediation",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get fix-command suggestions for a finding",
)
async def get_finding_remediation(
    finding_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    from src.dashboard.remediation import suggest_for_finding

    finding = _find_finding_by_id(services.query.output_root, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id, "suggestions": suggest_for_finding(finding)}


@router.put(
    "/bulk",
    response_model=list[dict[str, Any]],
    responses={401: {"model": ErrorResponse}},
    summary="Bulk update findings",
)
async def bulk_update_findings(
    payload: dict[str, Any],
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> list[dict[str, Any]]:
    """Apply updates to multiple findings."""
    ids = payload.get("ids", [])
    updates = {k: v for k, v in payload.items() if k != "ids"}
    results = []

    for fid in ids:
        try:
            res = await update_finding(fid, updates, _auth=_auth, services=services)
            results.append(res)
        except HTTPException:
            continue

    return results


@router.put(
    "/{finding_id}",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Update a finding",
)
async def update_finding(
    finding_id: str,
    update_data: dict[str, Any],
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Update finding metadata (status, severity, etc.) on disk."""
    output_root = services.query.output_root

    # Locate the finding by searching through all targets and runs
    # Note: In a production system, this should be indexed in a database.
    found = False
    target_name = ""
    run_name = ""
    target_finding_idx = -1
    finding_payload = {}
    findings_list = []
    findings_file_path = None

    for target_entry in output_root.iterdir():
        if not target_entry.is_dir():
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir():
                continue
            findings_path = run_entry / "findings.json"
            if findings_path.exists():
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    for idx, f in enumerate(findings):
                        # Construct ID similar to _normalize_finding_payload to match
                        fid = (
                            f.get("id")
                            or f.get("finding_id")
                            or f"{target_entry.name}-{run_entry.name}-{idx + 1}"
                        )
                        if fid == finding_id:
                            found = True
                            target_name = target_entry.name
                            run_name = run_entry.name
                            target_finding_idx = idx
                            finding_payload = f
                            findings_list = findings
                            findings_file_path = findings_path
                            break
                except Exception:  # noqa: S112
                    continue
            if found:
                break
        if found:
            break

    if not found:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Apply updates
    for key, value in update_data.items():
        if key not in {"id", "finding_id"}:  # Don't allow ID changes
            finding_payload[key] = value

    # Save back to disk
    try:
        if findings_file_path:
            findings_list[target_finding_idx] = finding_payload
            findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
        else:
            raise ValueError("Finding path not found")
    except Exception as e:
        logger.error("Failed to save updated finding: %s", e)
        raise HTTPException(status_code=500, detail="Failed to persist finding update")

    # Hook into False Positive Learning Integration Mesh-Wide Sync
    is_fp_triage = (
        finding_payload.get("decision") == "DROP"
        or finding_payload.get("status") == "false_positive"
        or finding_payload.get("lifecycle_state") == "FALSE_POSITIVE"
    )
    if is_fp_triage:
        try:
            from src.learning.integration import LearningIntegration

            learning = LearningIntegration.get_or_create()
            if learning and learning.config.enabled:
                response_status = finding_payload.get("response_status") or finding_payload.get(
                    "status_code"
                )
                body = (
                    finding_payload.get("evidence")
                    or finding_payload.get("body")
                    or finding_payload.get("description", "")
                )
                category = finding_payload.get("category", "general")
                # Schedule the async manual FP registration
                import asyncio

                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(
                        learning._fp_tracker.add_manual_fp(
                            category=category,
                            status_code=int(response_status) if response_status else None,
                            body_indicator=body,
                        )
                    )
                except RuntimeError:
                    # In a synchronous context or no running event loop, execute synchronously
                    asyncio.run(
                        learning._fp_tracker.add_manual_fp(
                            category=category,
                            status_code=int(response_status) if response_status else None,
                            body_indicator=body,
                        )
                    )
        except Exception as e:
            logger.warning("Mesh FP Sync: Failed to propagate manual FP: %s", e)

    return _normalize_finding_payload(
        finding_payload, target_name=target_name, run_name=run_name, index=target_finding_idx + 1
    )


@router.delete(
    "/{finding_id}",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Delete a finding",
)
async def delete_finding(
    finding_id: str,
    _auth: Any = Depends(require_admin),
    services: Any = Depends(get_queue_client),
) -> dict[str, bool]:
    """Remove a finding from disk."""
    output_root = services.query.output_root
    found = False
    findings_file_path = None
    findings_list = []
    target_finding_idx = -1

    for target_entry in output_root.iterdir():
        if not target_entry.is_dir():
            continue
        for run_entry in target_entry.iterdir():
            if not run_entry.is_dir():
                continue
            findings_path = run_entry / "findings.json"
            if findings_path.exists():
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    for idx, f in enumerate(findings):
                        fid = (
                            f.get("id")
                            or f.get("finding_id")
                            or f"{target_entry.name}-{run_entry.name}-{idx + 1}"
                        )
                        if fid == finding_id:
                            found = True
                            target_finding_idx = idx
                            findings_list = findings
                            findings_file_path = findings_path
                            break
                except Exception:  # noqa: S112
                    continue
            if found:
                break
        if found:
            break

    if not found:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        if findings_file_path:
            findings_list.pop(target_finding_idx)
            findings_file_path.write_text(json.dumps(findings_list, indent=2), encoding="utf-8")
        else:
            raise ValueError("Finding path not found")
    except Exception as e:
        logger.error("Failed to delete finding: %s", e)
        raise HTTPException(status_code=500, detail="Failed to delete finding from disk")

    return {"deleted": True}

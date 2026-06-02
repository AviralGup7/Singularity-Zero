import logging
from typing import Any

from fastapi import APIRouter, Depends, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings.helpers import (
    _collect_timeline_events,
    _seeded_timeline_events,
    _telemetry_timeline_events,
)
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


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
    tenant_id = (_auth or {}).get("tenant_id", "default")
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
        tenant_id=tenant_id,
    )
    telemetry_events = _telemetry_timeline_events(
        services.list_jobs(),
        job_id=job_id,
        severity=severity,
        target=target,
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_id,
    )
    if telemetry_events:
        merged = {str(item.get("id")): item for item in [*events, *telemetry_events]}
        events = sorted(
            merged.values(), key=lambda item: str(item.get("timestamp", "")), reverse=True
        )[offset : offset + limit]
    if not events and offset == 0:
        return _seeded_timeline_events(limit, offset)
    return events

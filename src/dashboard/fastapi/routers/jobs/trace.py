"""Endpoint for retrieving job telemetry trace deep links."""

import json
import os
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_enriched_job
from src.dashboard.fastapi.schemas import ErrorResponse

router = APIRouter(prefix="/api/jobs")


def _build_jaeger_url(job_id: str, job: dict[str, Any]) -> dict[str, str]:
    """Resolve Jaeger tracing deep links defensively from environments."""
    base_url = os.getenv("CYBER_JAEGER_URL", "http://localhost:16686").rstrip("/")
    service_name = os.getenv("CYBER_OTEL_SERVICE_NAME", "cyber-pipeline")
    telemetry = job.get("progress_telemetry")
    trace_id = str(
        job.get("trace_id")
        or job.get("otel_trace_id")
        or (telemetry.get("trace_id") if isinstance(telemetry, dict) else "")
        or ""
    ).strip()

    if trace_id:
        return {
            "job_id": job_id,
            "trace_id": trace_id,
            "trace_url": f"{base_url}/trace/{quote(trace_id)}",
            "mode": "trace",
        }

    tags = quote(json.dumps({"job.id": job_id}, separators=(",", ":")))
    query = urlencode({"service": service_name})
    return {
        "job_id": job_id,
        "trace_id": "",
        "trace_url": f"{base_url}/search?{query}&tags={tags}",
        "mode": "search",
    }


@router.get(
    "/{job_id}/trace",
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get the Jaeger deep link for a job trace",
)
async def get_job_trace_link(
    job_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, str]:
    tenant_id = (_auth or {}).get("tenant_id", "default")
    from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
    from fastapi import HTTPException

    job = await get_enriched_job(job_id, services)
    job_target = str(job.get("target_name") or job.get("hostname") or job.get("target") or "")
    if not is_target_owned_by_tenant(job_target, tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    return _build_jaeger_url(job_id, job)

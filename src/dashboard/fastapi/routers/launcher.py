"""Router for serving launcher artifacts and pipeline reports.

Security boundary (S-1):
  * Every route here requires authentication.
  * Every route enforces tenant ownership of the requested resource.
  * A request that cannot be attributed to a tenant is rejected
    (fail-closed) when API security is enabled.
"""

import logging

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import FileResponse

from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
from src.dashboard.fastapi.routers.utils import job_target_name

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/launcher/{job_id}/{filename}", include_in_schema=False)
async def serve_launcher_artifact(
    job_id: str,
    filename: str,
    request: Request,
    _auth: dict[str, str] = Depends(require_auth),
) -> Response:
    """Serve specific log and metadata files for a background job run.

    Requires authentication AND tenant ownership of the job's target.
    """
    # Sanity check to prevent path traversal and null-byte injection
    if any(char in job_id for char in ("/", "\\", "..", "\x00")) or any(
        char in filename for char in ("/", "\\", "..", "\x00")
    ):
        return Response(status_code=400, content="Invalid parameters")

    tenant_id = (_auth or {}).get("tenant_id", "default")
    # Resolve the job's target so we can enforce tenant ownership.
    try:
        services = getattr(request.app.state, "services", None)
        job = services.get_job(job_id) if services is not None else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Launcher artifact: job lookup failed job=%s: %s", job_id, exc)
        job = None
    if not isinstance(job, dict):
        # Cannot attribute the artifact to a tenant — reject (fail-closed).
        logger.warning("Launcher artifact: no tenant-attributable job %s", job_id)
        return Response(status_code=404)
    target_name = job_target_name(job)
    if not is_target_owned_by_tenant(target_name, tenant_id):
        logger.warning(
            "Launcher artifact: tenant boundary violation job=%s target=%s tenant=%s",
            job_id,
            target_name,
            tenant_id,
        )
        return Response(status_code=404)

    config = request.app.state.config
    safe_path = (config.output_root / "launcher" / job_id / filename).resolve()
    if safe_path.is_file() and safe_path.is_relative_to(config.output_root.resolve()):
        return FileResponse(path=safe_path)
    return Response(status_code=404)


@router.get("/reports/{target_name:path}/{file_path:path}", include_in_schema=False)
async def serve_pipeline_report(
    target_name: str,
    file_path: str,
    request: Request,
    _auth: dict[str, str] = Depends(require_auth),
) -> Response:
    """Serve static pipeline vulnerability scan HTML reports.

    Requires authentication AND tenant ownership of *target_name*.
    Without a valid tenant attribution the request is rejected.
    """
    tenant_id = (_auth or {}).get("tenant_id", "default")
    if not is_target_owned_by_tenant(target_name, tenant_id):
        logger.warning(
            "Report access: tenant boundary violation target=%s tenant=%s",
            target_name,
            tenant_id,
        )
        return Response(status_code=404)

    config = request.app.state.config
    base = config.output_root.resolve()
    full_path = (base / target_name / file_path).resolve()
    if full_path.is_file() and full_path.is_relative_to(base):
        return FileResponse(path=full_path)
    return Response(status_code=404)

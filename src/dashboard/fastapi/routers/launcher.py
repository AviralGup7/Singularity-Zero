"""Router for serving launcher artifacts and pipeline reports."""

import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import FileResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/launcher/{job_id}/{filename}", include_in_schema=False)
async def serve_launcher_artifact(job_id: str, filename: str, request: Request) -> Response:
    """Serve specific log and metadata files for a background job run."""
    config = request.app.state.config
    safe_path = (config.output_root / "launcher" / job_id / filename).resolve()
    if safe_path.is_file() and safe_path.is_relative_to(config.output_root.resolve()):
        return FileResponse(path=safe_path)
    return Response(status_code=404)


@router.get("/reports/{target_name:path}/{file_path:path}", include_in_schema=False)
async def serve_pipeline_report(target_name: str, file_path: str, request: Request) -> Response:
    """Serve static pipeline vulnerability scan HTML reports."""
    config = request.app.state.config
    base = config.output_root.resolve()
    full_path = (base / target_name / file_path).resolve()
    if full_path.is_file() and full_path.is_relative_to(base):
        return FileResponse(path=full_path)
    return Response(status_code=404)

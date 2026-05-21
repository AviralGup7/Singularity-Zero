"""Report library endpoints."""

from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.reporting.report_artifacts import build_report_library

router = APIRouter(prefix="/api/reports")


@router.get(
    "/library",
    summary="List signed report artefacts across pipeline runs",
)
async def list_report_library(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    return build_report_library(services.query.output_root)

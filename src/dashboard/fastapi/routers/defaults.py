"""API Defaults for the FastAPI dashboard."""

import logging
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.dashboard.fastapi.dependencies import require_auth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/defaults", tags=["Defaults"])


class ApiDefaults(BaseModel):
    default_mode: str
    form_defaults: dict[str, str]


@router.get(
    "",
    response_model=ApiDefaults,
    summary="Get form and system defaults",
)
async def get_defaults(_auth: Any = Depends(require_auth)) -> ApiDefaults:
    """Return default settings for forms and UI components."""
    return ApiDefaults(
        default_mode="quick",
        form_defaults={
            "scan_mode": "quick",
            "threads": "10",
            "timeout": "300",
            "retries": "3",
        },
    )

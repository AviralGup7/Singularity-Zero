"""Endpoint for retrieving historical stage duration metrics."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.eta_engine import get_eta_engine
from src.dashboard.feature_flags import FeatureFlags
from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.schemas import ErrorResponse

router = APIRouter(prefix="/api/jobs")


@router.get(
    "/historical-durations",
    responses={501: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get historical stage durations",
    description="Return historical duration statistics for each pipeline stage based on past job runs. Requires ENABLE_DURATION_FORECAST=true.",
)
async def get_historical_durations(
    _auth: Any = Depends(require_auth),
) -> Any:
    """Return historical duration statistics if enabled by FeatureFlags."""
    if not FeatureFlags.ENABLE_DURATION_FORECAST():
        raise HTTPException(
            status_code=501,
            detail="Duration forecast is disabled. Set ENABLE_DURATION_FORECAST=true",
        )

    eta_engine = get_eta_engine()
    data = await eta_engine.get_historical_durations()
    return data

"""FastAPI router for real-time Chameleon Evasion Telemetry."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.core.frontier.chameleon import _chameleon
from src.dashboard.fastapi.dependencies import require_auth

router = APIRouter(prefix="/api/evasion", tags=["Evasion Telemetry"])


@router.get(
    "/metrics",
    summary="Get WAF evasion effectiveness metrics",
)
async def get_evasion_metrics(_auth: Any = Depends(require_auth)) -> dict[str, Any]:
    """
    Returns aggregated and per-target/per-session WAF evasion benchmarks.
    Calculates evasion success rates per target/session.
    """
    try:
        raw_metrics = _chameleon.get_metrics()
        processed = {}
        for key, entry in raw_metrics.items():
            total = entry.get("total_requests", 0)
            successes = entry.get("successes", 0)

            # calculate dynamic evasion success rate
            success_rate = 0.0
            if total > 0:
                success_rate = round(((successes) / total) * 100.0, 2)

            processed[key] = {
                **entry,
                "evasion_success_rate": success_rate,
            }
        return {"metrics": processed}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch evasion metrics: {e}")


@router.post(
    "/reset",
    summary="Reset Chameleon Evasion Telemetry metrics",
)
async def reset_evasion_metrics(_auth: Any = Depends(require_auth)) -> dict[str, Any]:
    """Resets the WAF evasion metrics repository."""
    try:
        _chameleon.reset_metrics()
        return {"status": "success", "message": "Evasion metrics reset successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset evasion metrics: {e}")

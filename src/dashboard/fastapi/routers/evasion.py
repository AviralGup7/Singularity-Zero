"""FastAPI router for real-time Chameleon Evasion Telemetry."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import require_auth
from src.execution.frontier.chameleon import _chameleon

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/evasion", tags=["Evasion Telemetry"])

# ---------------------------------------------------------------------------
# In-memory hunt-mode state (toggled via POST /api/evasion/hunt-mode)
# ---------------------------------------------------------------------------

_hunt_lock = threading.Lock()
_hunt_enabled: bool = False
_hunt_reason: str = ""
_hunt_actor: str = ""
_hunt_activated_at: float | None = None


class HuntModeRequest(BaseModel):
    """Body for the hunt-mode toggle endpoint."""

    enabled: bool
    reason: str | None = Field(default=None, max_length=512)
    actor: str | None = Field(default=None, max_length=128)


def _get_hunt_mode_details() -> dict[str, Any]:
    """Return serialisable hunt-mode details."""
    return {
        "enabled": _hunt_enabled,
        "skip_subdomain_enumeration": True,
        "skip_passive_checks": False,
        "high_value_categories": [
            "authentication",
            "authorization",
            "injection",
            "sensitive-data-exposure",
            "broken-access-control",
        ],
        "low_hanging_fruit_path_keywords": [
            "admin",
            "auth",
            "login",
            "oauth",
            "api",
            "user",
            "account",
            "internal",
            "debug",
        ],
        "low_hanging_fruit_min_severity": "medium",
        "low_hanging_fruit_min_confidence": 0.7,
        "low_hanging_fruit_max_findings": 50,
        "deduplicate_against_history": True,
    }


def _build_metrics_response() -> dict[str, Any]:
    """Build the evasion metrics response."""
    raw_metrics = _chameleon.get_metrics()
    processed: dict[str, Any] = {}
    for key, entry in raw_metrics.items():
        total = entry.get("total_requests", 0)
        successes = entry.get("successes", 0)
        success_rate = 0.0
        if total > 0:
            success_rate = round((successes / total) * 100.0, 2)
        processed[key] = {
            **entry,
            "evasion_success_rate": success_rate,
        }
    return processed


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
        return {"metrics": _build_metrics_response()}
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


@router.post(
    "/hunt-mode",
    summary="Toggle bug-bounty hunt mode on or off",
)
async def set_hunt_mode(
    payload: HuntModeRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Enable or disable hunt mode.

    Hunt mode prioritises high-value categories, skips low-yield stages,
    and enforces a budget to maximise payout per hour.
    """
    global _hunt_enabled, _hunt_reason, _hunt_actor, _hunt_activated_at  # noqa: PLW0603

    with _hunt_lock:
        _hunt_enabled = payload.enabled
        _hunt_reason = payload.reason or ""
        _hunt_actor = payload.actor or ""
        _hunt_activated_at = time.time() if payload.enabled else None

    # Build hunt-mode details when enabled
    hunt_mode_details: dict[str, Any] | None = None
    if payload.enabled:
        hunt_mode_details = _get_hunt_mode_details()

    # Return the full evasion metrics response with hunt-mode state merged
    try:
        processed = _build_metrics_response()
        hunt_mode_response: dict[str, Any] = {
            "metrics": processed,
            "hunt_mode": payload.enabled,
            "hunt_mode_details": hunt_mode_details,
        }
    except Exception:
        logger.debug("Failed to build hunt mode metrics response", exc_info=True)
        hunt_mode_response = {
            "metrics": {},
            "hunt_mode": payload.enabled,
            "hunt_mode_details": hunt_mode_details,
        }

    return {
        "enabled": payload.enabled,
        "reason": payload.reason,
        "hunt_mode": hunt_mode_response,
    }

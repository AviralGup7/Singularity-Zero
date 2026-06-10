"""Self-healing pipeline controller dashboard endpoints."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import require_auth

router = APIRouter(prefix="/api/health/self-healing", tags=["Self-Healing"])


@router.get(
    "",
    response_model=dict[str, Any],
    responses={401: {"description": "Unauthorized"}},
)
async def self_healing_snapshot(
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return the latest autonomous recovery snapshot."""
    controller = getattr(request.app.state, "self_healing_controller", None)
    if controller is None:
        return {
            "status": "unknown",
            "metrics": [],
            "findings": [],
            "corrections": [],
            "controller": "disabled",
        }
    return cast(dict[str, Any], controller.last_snapshot.as_dict())


@router.post(
    "/evaluate",
    response_model=dict[str, Any],
    responses={401: {"description": "Unauthorized"}},
)
async def evaluate_self_healing(
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Run one immediate controller pass."""
    controller = getattr(request.app.state, "self_healing_controller", None)
    if controller is None:
        return {"status": "unknown", "controller": "disabled"}
    snapshot = await controller.evaluate_once()
    return cast(dict[str, Any], snapshot.as_dict())


@router.get(
    "/tile",
    response_model=dict[str, Any],
    responses={401: {"description": "Unauthorized"}},
)
async def self_healing_tile(
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Compact health tile payload for dashboard clients."""
    controller = getattr(request.app.state, "self_healing_controller", None)
    if controller is None:
        return {
            "label": "Self-Healing",
            "status": "unknown",
            "active_findings": 0,
            "last_action": None,
        }
    snapshot = controller.last_snapshot
    last_action = snapshot.corrections[-1] if snapshot.corrections else None
    return {
        "label": "Self-Healing",
        "status": snapshot.status.value,
        "active_findings": len(snapshot.findings),
        "metric_count": len(snapshot.metrics),
        "last_action": {
            "action": last_action.action.value,
            "success": last_action.success,
            "message": last_action.message,
            "executed_at": last_action.executed_at,
        }
        if last_action
        else None,
    }


class ForceOpenRequest(BaseModel):
    """Body for the force-open tool circuit breaker endpoint."""

    reason: str = Field(default="dashboard-operator", max_length=512)
    duration_seconds: float | None = Field(
        default=None,
        ge=0.0,
        description=(
            "Optional fixed cool-down window. Defaults to the breaker's "
            "configured recovery_timeout when omitted. 0 = indefinite "
            "(stays OPEN until reset)."
        ),
    )


@router.get(
    "/circuit-breakers",
    response_model=dict[str, Any],
    responses={401: {"description": "Unauthorized"}},
)
async def list_circuit_breakers(
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return a serializable snapshot of every per-tool circuit breaker.

    The response is sourced from the bound
    :class:`~src.pipeline.services.tool_execution.ToolExecutionService` (or
    the module-level default if the controller has none wired).
    """
    service = getattr(request.app.state, "tool_execution_service", None)
    if service is None:
        from src.pipeline.services.tool_execution import ToolExecutionService

        service = ToolExecutionService()
    snapshot = service.breaker_snapshot()
    return {
        "tools": {
            name: (stats.as_dict() if hasattr(stats, "as_dict") else dict(stats))  # type: ignore[arg-type]
            for name, stats in snapshot.items()
        },
        "count": len(snapshot),
    }


@router.post(
    "/circuit-breakers/{tool_name}/force-open",
    response_model=dict[str, Any],
    responses={401: {"description": "Unauthorized"}},
)
async def force_open_tool_breaker(
    tool_name: str,
    payload: ForceOpenRequest,
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Trip a tool's circuit breaker.

    The ``TRIP_TOOL_CIRCUIT_BREAKER`` corrective action calls the same
    backend.  Operators can invoke this endpoint to manually cool down a
    tool that is hammering a rate-limited upstream.
    """
    service = getattr(request.app.state, "tool_execution_service", None)
    if service is None:
        from src.pipeline.services.tool_execution import ToolExecutionService

        service = ToolExecutionService()
    breaker = service.force_open_breaker(
        tool_name,
        payload.reason,
        duration_seconds=payload.duration_seconds,
    )
    stats = breaker.stats()
    return {
        "tool": tool_name,
        "state": stats.state,
        "reason": payload.reason,
        "duration_seconds": payload.duration_seconds,
        "forced_open": stats.forced_open,
    }


@router.post(
    "/circuit-breakers/{tool_name}/reset",
    response_model=dict[str, Any],
    responses={401: {"description": "Unauthorized"}},
)
async def reset_tool_breaker(
    tool_name: str,
    request: Request,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Manually reset a tool's breaker back to CLOSED."""
    service = getattr(request.app.state, "tool_execution_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="Tool execution service not available")
    breaker = service.reset_breaker(tool_name)
    stats = breaker.stats()
    return {
        "tool": tool_name,
        "state": stats.state,
    }

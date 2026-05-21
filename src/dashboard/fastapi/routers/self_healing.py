"""Self-healing pipeline controller dashboard endpoints."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/health/self-healing", tags=["Self-Healing"])


@router.get("")
async def self_healing_snapshot(request: Request) -> dict[str, Any]:
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


@router.post("/evaluate")
async def evaluate_self_healing(request: Request) -> dict[str, Any]:
    """Run one immediate controller pass."""
    controller = getattr(request.app.state, "self_healing_controller", None)
    if controller is None:
        return {"status": "unknown", "controller": "disabled"}
    snapshot = await controller.evaluate_once()
    return cast(dict[str, Any], snapshot.as_dict())


@router.get("/tile")
async def self_healing_tile(request: Request) -> dict[str, Any]:
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

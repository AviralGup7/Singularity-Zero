"""Process health / readiness / survival surface.

- /_healthz  liveness (process up)
- /_readyz   recovery READY + invariants + lag + disk
- /_survivalz survival mode dump

Also used as FastAPI router; dashboard includes these aliases.
"""

from __future__ import annotations

import time
from typing import Any

from src.core.frontier.frontier_only import get_frontier_only_state
from src.core.recovery.survival import get_survival_state, is_survival
from src.core.runtime.resource_guard import inspect_resources

_START = time.time()


def liveness() -> dict[str, Any]:
    return {
        "status": "ok",
        "uptime": round(time.time() - _START, 3),
    }


def readiness(
    *,
    recovery_state: str = "READY",
    invariants_ok: bool = True,
    lag: float = 0.0,
    max_lag: float = 30.0,
    leader_ok: bool = True,
) -> dict[str, Any]:
    resources = inspect_resources()
    survival = is_survival()
    ready = (
        recovery_state == "READY"
        and invariants_ok
        and lag < max_lag
        and leader_ok
        and resources.ok
        and not survival
    )
    return {
        "status": "ready" if ready else "not_ready",
        "recovery_state": recovery_state,
        "invariants_ok": invariants_ok,
        "lag": lag,
        "leader_ok": leader_ok,
        "disk_free_ok": resources.ok,
        "survival": survival,
    }


def survivalz() -> dict[str, Any]:
    body = get_survival_state().to_dict()
    frontier = get_frontier_only_state()
    body["frontier_only"] = frontier.to_dict()
    try:
        from src.core.findings.spill import spill_enabled

        body["findings_spill_enabled"] = spill_enabled()
    except Exception:
        body["findings_spill_enabled"] = False
    return body


def survival_headers() -> dict[str, str]:
    headers = get_survival_state().headers()
    headers.update(get_frontier_only_state().headers())
    return headers


try:
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse

    router = APIRouter(tags=["System"])

    @router.get("/_healthz")
    async def _healthz() -> dict[str, Any]:
        return liveness()

    @router.get("/_readyz")
    async def _readyz() -> JSONResponse:
        body = readiness()
        code = 200 if body["status"] == "ready" else 503
        return JSONResponse(status_code=code, content=body, headers=survival_headers())

    @router.get("/_survivalz")
    async def _survivalz() -> dict[str, Any]:
        return survivalz()

except ImportError:  # FastAPI optional for unit tests
    router = None  # type: ignore[assignment]


__all__ = ["liveness", "readiness", "router", "survival_headers", "survivalz"]

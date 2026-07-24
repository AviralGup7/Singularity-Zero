"""Dashboard package facade.

Re-exports the ``main`` entry point for the FastAPI dashboard server.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "dashboard",
    "version": "3.1.0",
    "description": (
        "FastAPI dashboard with WebSocket, controls, forensics, "
        "reporting integrations, and the 3D attack-chain cockpit."
    ),
    "layer": "dashboard",
    "submodules": (
        "fastapi",
        "forensics",
        "output",
        "registry",
        "services",
    ),
    "public_api": ("main",),
    "depends_on": ("core",),
    "entry_points": (
        "cyber-dashboard-fastapi",
        "cstp-dashboard",
    ),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify dashboard subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        from src.dashboard.fastapi.app import create_app  # noqa: F401
        from src.dashboard.health import check as _health_check  # noqa: F401

        return {
            "status": "ok",
            "module": "dashboard",
            "version": "3.1.0",
            "details": {
                "fastapi_app": "available",
                "health_module": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "dashboard",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

from src.dashboard.fastapi.main import main

__all__ = ["main"]

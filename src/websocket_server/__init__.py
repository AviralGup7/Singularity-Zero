"""Real-time WebSocket support for the cyber security test pipeline.

Provides WebSocket connection management, authentication, message protocol,
heartbeat monitoring, reconnection support, broadcasting, and FastAPI integration
for real-time scan progress, job status, log streaming, and dashboard updates.

Usage:
    from fastapi import FastAPI
    from src.websocket_server.integration import setup_websocket_routes

    app = FastAPI()
    setup_websocket_routes(app)
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "websocket_server",
    "version": "3.1.0",
    "description": (
        "Real-time WebSocket support for scan progress and dashboard "
        "updates: connection management, auth, heartbeat, reconnection, "
        "and message broadcasting."
    ),
    "layer": "websocket",
    "submodules": ("integration",),
    "public_api": (
        "ConnectionManager",
        "AckMessage",
        "BaseMessage",
        "ErrorMessage",
        "HeartbeatMessage",
        "LogMessage",
        "ProgressMessage",
        "StatusMessage",
        "SubscribeMessage",
        "UnsubscribeMessage",
    ),
    "depends_on": ("core",),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify websocket_server subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        from src.websocket_server.manager import ConnectionManager  # noqa: F401
        from src.websocket_server.protocol import BaseMessage  # noqa: F401

        return {
            "status": "ok",
            "module": "websocket_server",
            "version": "3.1.0",
            "details": {
                "connection_manager": "available",
                "protocol": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "websocket_server",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import (
    AckMessage,
    BaseMessage,
    ErrorMessage,
    HeartbeatMessage,
    LogMessage,
    ProgressMessage,
    StatusMessage,
    SubscribeMessage,
    UnsubscribeMessage,
)

__all__ = [
    "AckMessage",
    "BaseMessage",
    "ConnectionManager",
    "ErrorMessage",
    "HeartbeatMessage",
    "LogMessage",
    "ProgressMessage",
    "StatusMessage",
    "SubscribeMessage",
    "UnsubscribeMessage",
]

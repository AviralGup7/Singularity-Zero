"""WebSocket endpoint discovery spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Map the WebSocket handshake path and check whether auth and origin checks are enforced."


register_spec(
    (
        "websocket_endpoint_discovery",
        "exposure",
        _severity,
        "WebSocket endpoint discovery",
        _description,
    )
)

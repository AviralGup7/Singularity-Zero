"""Realtime fan-out facade over the websocket server.

Dashboard lifespan mounts this; it must not reimplement rooms.
"""

from __future__ import annotations

from typing import Any


def get_manager() -> Any:
    from src.websocket_server.manager import ConnectionManager

    return ConnectionManager


def get_broadcaster() -> Any:
    from src.websocket_server.broadcaster import Broadcaster

    return Broadcaster


__all__ = ["get_broadcaster", "get_manager"]

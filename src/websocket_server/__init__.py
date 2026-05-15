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

from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import (
    AckMessage,
    BaseMessage,
    ErrorMessage,
    HeartbeatMessage,
    LogMessage,
    Message,
    MessageType,
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
    "Message",
    "MessageType",
    "ProgressMessage",
    "StatusMessage",
    "SubscribeMessage",
    "UnsubscribeMessage",
]

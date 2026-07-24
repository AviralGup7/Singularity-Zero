"""FastAPI integration for WebSocket support.

Provides WebSocket router setup, dependency injection for authentication,
event handlers for connection lifecycle, and integration hooks for the
queue_system job events and pipeline scan progress.

Usage::

    from fastapi import FastAPI
    from src.websocket_server.integration import setup_websocket_routes, get_ws_services

    app = FastAPI()
    ws_services = setup_websocket_routes(app, jwt_secret=os.environ.get("WS_JWT_SECRET"))

Backward-compatible re-exports: ``setup_websocket_routes`` and ``WSServices``
are importable from ``src.websocket_server.integration``.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from starlette.websockets import WebSocket

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.broadcaster import Broadcaster
from src.websocket_server.handlers import WebSocketHandler
from src.websocket_server.heartbeat import HeartbeatMonitor
from src.websocket_server.integration.admin import register_admin_routes
from src.websocket_server.integration.models import (
    AdminConfigPayload,
    BroadcastPayload,
    JobTenantResolver,
)
from src.websocket_server.integration.pipeline_hook import integrate_with_pipeline_progress
from src.websocket_server.integration.queue_hook import integrate_with_queue_system
from src.websocket_server.integration.services import WSServices, _default_job_tenant_resolver
from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import LogMessage, ProgressMessage, StatusMessage
from src.websocket_server.reconnect import ReconnectionManager

logger = get_pipeline_logger(__name__)

__all__ = [
    "AdminConfigPayload",
    "BroadcastPayload",
    "JobTenantResolver",
    "WSServices",
    "_default_job_tenant_resolver",
    "get_ws_services",
    "integrate_with_pipeline_progress",
    "integrate_with_queue_system",
    "setup_websocket_routes",
]

_ws_services: WSServices | None = None


def get_ws_services() -> WSServices | None:
    """Return the global WSServices instance, or None if not yet initialized."""
    return _ws_services


def setup_websocket_routes(
    app: FastAPI,
    *,
    jwt_secret: str | None = None,
    admin_api_key: str | None = None,
    effective_admin_roles: Any | None = None,
    allowed_origins: set[str] | None = None,
) -> WSServices:
    """Wire up WebSocket routes, components, and return the shared WSServices.

    This is the main entry point for integrating WebSocket support into
    a FastAPI application.
    """
    global _ws_services

    from src.websocket_server.integration.services import WSServices

    manager = ConnectionManager()
    broadcaster = Broadcaster(manager)
    heartbeat = HeartbeatMonitor(manager)
    reconnect = ReconnectionManager()
    handler = WebSocketHandler(
        manager, broadcaster, heartbeat, reconnect, allowed_origins=allowed_origins
    )

    services = WSServices(
        manager=manager,
        broadcaster=broadcaster,
        heartbeat=heartbeat,
        handler=handler,
        reconnect=reconnect,
    )
    _ws_services = services

    # Store admin roles resolver on app state for use in route handlers
    if effective_admin_roles is not None:
        app.state.effective_admin_roles = effective_admin_roles

    # WebSocket endpoints
    @app.websocket("/ws/scan-progress")
    async def ws_scan_progress(websocket: WebSocket) -> None:
        await handler.handle_scan_progress(websocket)

    @app.websocket("/ws/job-status")
    async def ws_job_status(websocket: WebSocket) -> None:
        await handler.handle_job_status(websocket)

    @app.websocket("/ws/logs/{job_id}")
    async def ws_logs(websocket: WebSocket, job_id: str) -> None:
        await handler.handle_job_logs(websocket, job_id)

    @app.websocket("/ws/dashboard")
    async def ws_dashboard(websocket: WebSocket) -> None:
        await handler.handle_dashboard(websocket)

    @app.websocket("/ws/evasion-telemetry")
    async def ws_evasion_telemetry(websocket: WebSocket) -> None:
        await handler.handle_evasion_telemetry(websocket)

    # Health / metrics HTTP endpoints
    @app.get("/health/ws")
    async def ws_health() -> dict[str, Any]:
        from fastapi.responses import PlainTextResponse

        return {
            "status": "ok",
            "connections": manager.count(),
            "channels": broadcaster.channel_count(),
        }

    @app.get("/metrics")
    async def ws_metrics() -> dict[str, Any]:
        from fastapi.responses import PlainTextResponse

        return {
            "websocket_connections": manager.count(),
            "websocket_channels": broadcaster.channel_count(),
            "broadcaster_stats": broadcaster.stats(),
        }

    # Admin management routes
    register_admin_routes(app, services, admin_api_key=admin_api_key)

    # Application lifespan
    @asynccontextmanager
    async def lifespan(application: Any) -> Any:
        services.start_cleanup_loop()
        try:
            yield
        finally:
            services.shutdown()

    app.router.lifespan_context = lifespan

    # Telemetry integration hook
    try:
        from src.core.frontier.drl_evasion import set_telemetry_sink

        class WSTelemetrySink:
            def __init__(self, svc: WSServices) -> None:
                self._services = svc

            def emit(self, job_id: str, data: dict[str, Any]) -> None:
                self._services.broadcast_telemetry(job_id, data=data)

        set_telemetry_sink(WSTelemetrySink(services))
    except (ImportError, AttributeError):
        pass

    # Pipeline progress integration
    integrate_with_pipeline_progress(services)

    # Queue system integration
    integrate_with_queue_system(services)

    logger.info("WebSocket routes configured")
    return services

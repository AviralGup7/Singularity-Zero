"""WebSocket setup for the FastAPI dashboard."""

from fastapi import FastAPI

from src.dashboard.fastapi.security import api_security_enabled
from src.websocket_server.integration import (
    WSServices,
    integrate_with_pipeline_progress,
    setup_websocket_routes,
)


def setup_websocket(
    app: FastAPI,
    jwt_secret: str | None = None,
    api_keys: dict[str, str] | None = None,
    required_roles: set[str] | None = None,
    heartbeat_interval: float = 20.0,
    heartbeat_timeout: float = 45.0,
    max_connections_per_ip: int = 20,
    redis_url: str | None = None,
    redis_channel: str = "cyber-pipeline:ws:broadcast",
) -> WSServices | None:
    security_enabled = api_security_enabled()
    ws_api_keys = api_keys or {}
    ws_required_roles = required_roles
    if security_enabled and not ws_required_roles:
        ws_required_roles = {"read_only", "worker", "admin"}

    ws_services = setup_websocket_routes(
        app,
        jwt_secret=jwt_secret if security_enabled else None,
        api_keys=ws_api_keys or None,
        required_roles=ws_required_roles or None,
        heartbeat_interval=heartbeat_interval,
        heartbeat_timeout=heartbeat_timeout,
        max_connections_per_ip=max_connections_per_ip,
        redis_url=redis_url,
        redis_channel=redis_channel,
    )
    app.state.ws_services = ws_services

    if hasattr(app.state, "services") and hasattr(app.state.services, "jobs") and hasattr(app.state.services, "lock"):
        integrate_with_pipeline_progress(
            ws_services,
            job_state_store=app.state.services.jobs,
            lock=app.state.services.lock,
        )

    return ws_services

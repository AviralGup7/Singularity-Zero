"""Phase 3: WebSocket server startup — real-time client communication."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI

from src.websocket_server.integration import (
    WSServices,
    integrate_with_pipeline_progress,
)

logger = logging.getLogger(__name__)


async def startup_websocket(app: FastAPI, config: Any) -> WSServices | None:
    """WebSocket server — real-time client communication."""
    from src.dashboard.fastapi.security import api_security_enabled, app_secret_key
    from src.dashboard.fastapi.ws_setup import setup_websocket

    ws_services: WSServices | None = None
    try:
        ws_api_keys = {key: f"admin:{index}" for index, key in enumerate(config.admin_keys) if key}
        ws_required_roles = (
            {"viewer", "operator", "admin", "anonymous"} if api_security_enabled() else None
        )
        ws_services = setup_websocket(
            app,
            jwt_secret=app_secret_key()
            if api_security_enabled()
            else (config.api_key if config.api_key else None),
            api_keys=ws_api_keys or None,
            required_roles=ws_required_roles,
            heartbeat_interval=20.0,
            heartbeat_timeout=45.0,
            max_connections_per_ip=5 if api_security_enabled() else 20,
            redis_url=config.redis_url,
            redis_channel="cyber-pipeline:ws:broadcast",
        )
        app.state.ws_services = ws_services

        if (
            ws_services is not None
            and hasattr(app.state.services, "jobs")
            and hasattr(app.state.services, "lock")
        ):
            integrate_with_pipeline_progress(
                ws_services,
                job_state_store=app.state.services.jobs,
                lock=app.state.services.lock,
            )
    except Exception as exc:
        logger.warning("WebSocket server initialization failed: %s", exc)
        app.state.ws_services = None
    return ws_services

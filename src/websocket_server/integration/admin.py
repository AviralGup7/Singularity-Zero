"""Admin WebSocket authentication, authorization, and management endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request
from starlette.websockets import WebSocketState

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.integration.models import AdminConfigPayload, BroadcastPayload

logger = get_pipeline_logger(__name__)

_INTERNAL_PREFIXES = ("global:", "logs:", "dashboard:", "job:")


def _resolve_admin_roles(request: Request, effective_admin_roles: Any) -> list[str]:
    resolver = getattr(effective_admin_roles, "__call__", None)
    if callable(resolver):
        try:
            roles = resolver(request)
            if isinstance(roles, (list, tuple)):
                return [str(r) for r in roles]
        except Exception as exc:
            logger.debug("Admin role resolver failed: %s", exc)
    return []


def _audit_admin(action: str, request: Request, details: dict[str, Any] | None = None) -> None:
    client = getattr(request, "client", None)
    host = client.host if client else "unknown"
    logger.info(
        "ADMIN_AUDIT action=%s host=%s path=%s details=%s",
        action,
        host,
        request.url.path,
        details or {},
    )


def _require_admin(request: Request, action: str, *, admin_api_key: str | None = None) -> None:
    if admin_api_key:
        provided = request.headers.get("x-api-key", "")
        if provided != admin_api_key:
            _audit_admin(action, request, {"result": "denied", "reason": "bad_api_key"})
            raise HTTPException(status_code=403, detail="Invalid or missing API key")
    roles = _resolve_admin_roles(request, getattr(request.app.state, "effective_admin_roles", None))
    if "admin" not in roles and "superadmin" not in roles:
        _audit_admin(action, request, {"result": "denied", "reason": "insufficient_roles"})
        raise HTTPException(status_code=403, detail="Admin role required")
    _audit_admin(action, request, {"result": "granted"})


def register_admin_routes(app: Any, services: Any, *, admin_api_key: str | None = None) -> None:
    """Register admin WebSocket management endpoints on the FastAPI app.

    ``admin_api_key`` is required for admin route authentication. Admin
    routes should not rely on client-supplied role headers such as
    ``x-user-roles``; roles must come from server-side resolvers.
    """

    @app.get("/admin/websocket/connections")
    async def list_connections(request: Request) -> dict[str, Any]:
        _require_admin(request, "list_connections", admin_api_key=admin_api_key)
        return {"connections": services.manager.snapshot()}

    @app.delete("/admin/websocket/connections/{connection_id}")
    async def force_disconnect(connection_id: str, request: Request) -> dict[str, str]:
        _require_admin(request, "force_disconnect", admin_api_key=admin_api_key)
        ws = services.manager.get(connection_id)
        if ws is None:
            raise HTTPException(status_code=404, detail="Connection not found")
        try:
            if ws.client_state != WebSocketState.DISCONNECTED:
                await ws.close(code=4001, reason="Disconnected by admin")
        except Exception:
            logger.exception("Failed to close WebSocket connection %s", connection_id)
        services.manager.remove(connection_id)
        _audit_admin("force_disconnect", request, {"connection_id": connection_id})
        return {"status": "disconnected"}

    @app.post("/admin/websocket/broadcast")
    async def admin_broadcast(payload: BroadcastPayload, request: Request) -> dict[str, str]:
        _require_admin(request, "broadcast", admin_api_key=admin_api_key)
        channel = payload.channel
        if channel.startswith(_INTERNAL_PREFIXES):
            raise HTTPException(status_code=400, detail="Cannot broadcast to internal channels")
        services.broadcaster.publish(channel, payload.message)
        _audit_admin("broadcast", request, {"channel": channel})
        return {"status": "sent"}

    @app.get("/admin/websocket/stats")
    async def websocket_stats(request: Request) -> dict[str, Any]:
        _require_admin(request, "stats", admin_api_key=admin_api_key)
        return {"stats": services.broadcaster.stats()}

    @app.post("/admin/websocket/config")
    async def update_config(payload: AdminConfigPayload, request: Request) -> dict[str, str]:
        _require_admin(request, "update_config", admin_api_key=admin_api_key)
        if payload.max_connections_per_user is not None:
            services.manager.set_max_per_user(payload.max_connections_per_user)
        if payload.max_connections_per_ip is not None:
            services.manager.set_max_per_ip(payload.max_connections_per_ip)
        if payload.stale_timeout is not None:
            services.manager.set_stale_timeout(payload.stale_timeout)
        if payload.max_connection_attempts_per_minute is not None:
            services.manager.set_rate_limit(payload.max_connection_attempts_per_minute)
        _audit_admin("update_config", request, {"payload": payload.model_dump(exclude_none=True)})
        return {"status": "updated"}

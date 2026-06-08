"""FastAPI integration for WebSocket support.

Provides WebSocket router setup, dependency injection for authentication,
event handlers for connection lifecycle, and integration hooks for the
queue_system job events and pipeline scan progress.

Usage:
    import os

from fastapi import FastAPI
    from src.websocket_server.integration import setup_websocket_routes, get_ws_services

    app = FastAPI()
    ws_services = setup_websocket_routes(app, jwt_secret=os.environ.get("WS_JWT_SECRET"))

    # Later, to emit events:
    services.broadcast_job_status(job_id="abc", status="running", ...)
    services.broadcast_scan_progress(job_id="abc", stage="urls", percent=52, ...)
    services.broadcast_log(job_id="abc", line="Found 42 endpoints", source="stdout")
"""

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from starlette.websockets import WebSocket

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.broadcaster import Broadcaster
from src.websocket_server.handlers import WebSocketHandler
from src.websocket_server.heartbeat import HeartbeatMonitor
from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import (
    LogMessage,
    ProgressMessage,
    StatusMessage,
)
from src.websocket_server.reconnect import ReconnectionManager

logger = get_pipeline_logger(__name__)


# A simple callable that, given a job id, returns the tenant that owns it.
# Deployments can plug in a richer implementation (e.g. backed by the job
# state store) without having to subclass WSServices.
JobTenantResolver = Callable[[str], str | None]


def _default_job_tenant_resolver(job_id: str) -> str | None:
    """Best-effort default job-to-tenant resolver.

    Tries to look the job up in ``src.dashboard.job_state`` if it is
    available. Returns ``None`` (meaning "no tenant scoping") when the
    job is unknown or the dashboard module is not importable — this
    preserves backward-compatible behaviour for deployments that do not
    yet have multi-tenant job metadata.
    """
    try:
        from src.dashboard import job_state as dashboard_job_state
    except Exception:  # noqa: BLE001
        return None
    get_job = getattr(dashboard_job_state, "get_job", None)
    if not callable(get_job):
        return None
    try:
        job = get_job(job_id)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(job, dict):
        return None
    tenant = job.get("tenant_id") or job.get("tenant")
    if isinstance(tenant, str) and tenant:
        return tenant
    owner = job.get("owner_id") or job.get("user_id")
    if isinstance(owner, str) and owner:
        return owner
    return None


@dataclass
class WSServices:
    """Convenience access to all WebSocket infrastructure components.

    Attributes:
        manager: Connection manager for active connections.
        broadcaster: Message broadcaster for fan-out delivery.
        heartbeat: Heartbeat monitor for client liveness.
        reconnect: Reconnection manager for session resume.
        handler: Central WebSocket endpoint handler.
        job_tenant_resolver: Callable mapping ``job_id`` to a tenant id,
            used to namespace the previously global ``global`` /
            ``dashboard`` channels into ``global:<tenant>`` and
            ``dashboard:<tenant>`` to prevent cross-tenant leakage.
        default_tenant_id: Tenant id used as a fallback when the
            resolver returns ``None``. Set to ``"default"`` so
            deployments that have not yet enabled multi-tenant
            job metadata still see a single, predictable channel.
        _cleanup_task: Background task for periodic stale connection cleanup.
    """

    manager: ConnectionManager
    broadcaster: Broadcaster
    heartbeat: HeartbeatMonitor
    reconnect: ReconnectionManager
    handler: WebSocketHandler
    job_tenant_resolver: JobTenantResolver = field(
        default=_default_job_tenant_resolver, repr=False
    )
    default_tenant_id: str = "default"
    _cleanup_task: asyncio.Task[None] | None = field(default=None, repr=False)

    def _tenant_for_job(self, job_id: str) -> str:
        """Resolve a tenant id for ``job_id`` with a safe fallback."""
        try:
            resolved = self.job_tenant_resolver(job_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Job tenant resolver failed for %s: %s", job_id, exc)
            resolved = None
        if isinstance(resolved, str) and resolved:
            return resolved
        return self.default_tenant_id

    def broadcast_progress(
        self,
        job_id: str,
        stage: str = "",
        stage_label: str = "",
        percent: int = 0,
        processed: int | None = None,
        total: int | None = None,
        message: str = "",
        target: str = "",
        tenant_id: str | None = None,
    ) -> asyncio.Task[int]:
        """Broadcast a scan progress update to subscribed clients.

        Sends to both the job-specific channel and the tenant-scoped
        global channel (``global:<tenant>``).

        Args:
            job_id: Job identifier.
            stage: Current pipeline stage name.
            stage_label: Human-readable stage label.
            percent: Overall progress percentage (0-100).
            processed: Items processed in current stage.
            total: Total items in current stage.
            message: Optional status message.
            target: Target URL or hostname.
            tenant_id: Optional explicit tenant id. When ``None`` the
                configured job tenant resolver is used (falls back to
                ``default_tenant_id``).

        Returns:
            Task resolving to the number of connections that received the message.
        """
        msg = ProgressMessage(
            job_id=job_id,
            stage=stage,
            stage_label=stage_label,
            percent=percent,
            processed=processed,
            total=total,
            message=message,
            target=target,
        )
        tenant = tenant_id or self._tenant_for_job(job_id)
        return asyncio.create_task(
            self._broadcast_to_job_and_tenant(msg, job_id, tenant),
            name=f"ws-progress-{job_id}",
        )

    def broadcast_telemetry(
        self,
        model_id: str,
        weight_drift: float,
        l2_norm: float,
        action_distribution: list[float],
        metadata: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> asyncio.Task[int]:
        """Broadcast DRL Policy Telemetry.

        Args:
            model_id: Identifier of the DRL model.
            weight_drift: Synaptic weight drift metric.
            l2_norm: L2 norm drift metric.
            action_distribution: Active action distribution.
            metadata: Optional additional context.
            tenant_id: Optional explicit tenant id. Defaults to
                ``default_tenant_id`` because telemetry is a global
                channel concept rather than a per-job one.
        """
        from src.websocket_server.protocol import TelemetryMessage

        msg = TelemetryMessage(
            model_id=model_id,
            weight_drift=weight_drift,
            l2_norm=l2_norm,
            action_distribution=action_distribution,
            metadata=metadata or {},
        )
        tenant = tenant_id or self.default_tenant_id
        return asyncio.create_task(
            self.broadcaster.broadcast_to_group(f"global:{tenant}", msg),
            name=f"ws-telemetry-{model_id}",
        )

    def broadcast_status(
        self,
        job_id: str,
        status: str,
        previous_status: str = "",
        stage: str = "",
        stage_label: str = "",
        progress_percent: int = 0,
        error: str | None = None,
        target: str = "",
        metadata: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> asyncio.Task[int]:
        """Broadcast a job status change to subscribed clients.

        Sends to both the job-specific channel and the tenant-scoped
        global channel.

        Args:
            job_id: Job identifier.
            status: New job status.
            previous_status: Status before the transition.
            stage: Current pipeline stage.
            stage_label: Human-readable stage label.
            progress_percent: Overall progress percentage.
            error: Error message if the job failed.
            target: Target URL or hostname.
            metadata: Additional context.
            tenant_id: Optional explicit tenant id.

        Returns:
            Task resolving to the number of connections that received the message.
        """
        msg = StatusMessage(
            job_id=job_id,
            status=status,
            previous_status=previous_status,
            stage=stage,
            stage_label=stage_label,
            progress_percent=progress_percent,
            error=error,
            target=target,
            metadata=metadata or {},
        )
        tenant = tenant_id or self._tenant_for_job(job_id)
        return asyncio.create_task(
            self._broadcast_to_job_and_tenant(msg, job_id, tenant),
            name=f"ws-status-{job_id}",
        )

    def broadcast_log(
        self,
        job_id: str,
        line: str,
        source: str = "stdout",
        level: str = "info",
        tenant_id: str | None = None,
    ) -> asyncio.Task[int]:
        """Broadcast a log line to clients subscribed to the job's log channel.

        Args:
            job_id: Job identifier.
            line: Log line content.
            source: Log source ('stdout' or 'stderr').
            level: Log level ('info', 'warning', 'error').
            tenant_id: Optional explicit tenant id. When supplied, the
                log is also published to ``logs:<job_id>`` subscribers
                and the tenant-scoped global channel. Otherwise, only
                the ``logs:<job_id>`` channel is used.

        Returns:
            Task resolving to the number of connections that received the message.
        """
        msg = LogMessage(
            job_id=job_id,
            line=line,
            source=source,
            level=level,
        )
        if tenant_id is None:
            return asyncio.create_task(
                self.broadcaster.broadcast_to_group(f"logs:{job_id}", msg),
                name=f"ws-log-{job_id}",
            )
        tenant = tenant_id or self._tenant_for_job(job_id)

        async def _fanout() -> int:
            logs_sent = await self.broadcaster.broadcast_to_group(
                f"logs:{job_id}", msg
            )
            global_sent = await self.broadcaster.broadcast_to_group(
                f"global:{tenant}", msg
            )
            return logs_sent + global_sent

        return asyncio.create_task(_fanout(), name=f"ws-log-{job_id}")

    async def _broadcast_to_job_and_tenant(
        self,
        message: Any,
        job_id: str,
        tenant_id: str,
    ) -> int:
        """Broadcast to both a job-specific channel and a tenant-scoped global channel.

        Args:
            message: Message to broadcast.
            job_id: Job identifier for the job-specific channel.
            tenant_id: Tenant identifier for the global channel.

        Returns:
            Total number of connections that received the message.
        """
        job_sent = await self.broadcaster.broadcast_to_group(f"job:{job_id}", message)
        global_sent = await self.broadcaster.broadcast_to_group(
            f"global:{tenant_id}", message
        )
        return job_sent + global_sent

    async def _broadcast_to_job_and_global(
        self,
        message: Any,
        job_id: str,
    ) -> int:
        """Backward-compatible alias for tests/callers that still use the
        un-namespaced global channel. Internally uses
        ``default_tenant_id`` so behaviour is preserved for legacy
        single-tenant deployments."""
        return await self._broadcast_to_job_and_tenant(
            message, job_id, self.default_tenant_id
        )

    async def start_cleanup_loop(self, interval: float = 60.0) -> None:
        """Start a background task that periodically cleans up stale connections.

        Args:
            interval: Seconds between cleanup runs.
        """
        await self.broadcaster.start()

        async def _cleanup_loop() -> None:
            while True:
                try:
                    await asyncio.sleep(interval)
                    stale = await self.manager.cleanup_stale()
                    self.reconnect.cleanup_expired()
                    if stale:
                        logger.info("Cleanup removed %d stale connections", len(stale))
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.error("Cleanup loop error: %s", exc)

        self._cleanup_task = asyncio.create_task(
            _cleanup_loop(),
            name="ws-cleanup-loop",
        )

    async def shutdown(self) -> None:
        """Gracefully shut down all WebSocket infrastructure.

        Stops the cleanup loop, heartbeat monitors, and closes all
        active connections.
        """
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        await self.heartbeat.stop_all()
        await self.broadcaster.stop()
        await self.manager.close_all()
        logger.info("WebSocket services shut down")


def setup_websocket_routes(
    app: FastAPI,
    jwt_secret: str | None = None,
    api_keys: dict[str, str] | None = None,
    required_roles: set[str] | None = None,
    admin_required_roles: set[str] | None = None,
    admin_role_resolver: Callable[[Any], set[str] | None] | None = None,
    admin_audit_logger: Callable[[str, str, dict[str, Any]], None] | None = None,
    max_connections_per_user: int = 10,
    max_connections_per_ip: int = 20,
    heartbeat_interval: float = 30.0,
    heartbeat_timeout: float = 90.0,
    reconnect_window: float = 300.0,
    cleanup_interval: float = 60.0,
    redis_url: str | None = None,
    redis_channel: str = "ws:broadcasts",
    allowed_origins: set[str] | None = None,
    compression_options: dict[str, Any] | None = None,
    default_tenant_id: str = "default",
    job_tenant_resolver: JobTenantResolver | None = None,
    require_tls: bool | None = None,
) -> WSServices:
    """Set up WebSocket routes on a FastAPI application.

    Registers the following WebSocket endpoints:
        - /ws/scan-progress - Real-time scan progress updates
        - /ws/job-status - Job status change notifications
        - /ws/logs/{job_id} - Streaming logs for a specific job
        - /ws/dashboard - General dashboard updates

    Args:
        app: FastAPI application instance.
        jwt_secret: Secret key for JWT validation. If None, JWT auth is skipped.
        api_keys: Dict mapping API key strings to user IDs.
        required_roles: Roles required for WebSocket access.
        admin_required_roles: Roles required to call ``/admin/websocket/*``
            HTTP routes. Defaults to ``{"admin"}`` when ``None`` is
            passed *and* an admin resolver/auditor is configured; when
            the parameter is the empty set, admin auth is disabled
            (intentionally opt-out for local dev).
        admin_role_resolver: Optional callable that returns the set of
            roles for the current HTTP request. Receives the FastAPI
            ``Request`` and should return a ``set[str]`` (or ``None``
            when no roles are available). When ``None``, the admin
            routes are still protected by default and use the
            ``X-User-Roles`` header as a development convenience.
        admin_audit_logger: Optional callable invoked with
            ``(action, actor, details)`` for every admin route hit.
            Defaults to a structured ``logger.warning`` call so
            invocations of destructive admin endpoints always leave a
            trail.
        max_connections_per_user: Max concurrent connections per user.
        max_connections_per_ip: Max concurrent connections per IP.
        heartbeat_interval: Seconds between heartbeat pings.
        heartbeat_timeout: Seconds of inactivity before disconnecting.
        reconnect_window: Seconds a reconnection token remains valid.
        cleanup_interval: Seconds between stale connection cleanup runs.
        allowed_origins: Set of allowed origin URIs to mitigate CSWSH.
        compression_options: Optional compression options (e.g. permessage-deflate).
        default_tenant_id: Tenant id used for the previously-global
            ``global`` and ``dashboard`` channels. Channels become
            ``global:<tenant>`` and ``dashboard:<tenant>`` so a single
            ``global`` channel no longer leaks across tenants.
        job_tenant_resolver: Callable mapping ``job_id`` to a tenant id.
        require_tls: When truthy, the WebSocket upgrade must arrive
            over ``wss://`` (or via a TLS-terminating proxy that sets
            ``X-Forwarded-Proto: https``) in production.

    Returns:
        WSServices instance for emitting events programmatically.
    """
    manager = ConnectionManager(
        max_connections_per_user=max_connections_per_user,
        max_connections_per_ip=max_connections_per_ip,
    )

    broadcaster = Broadcaster(
        manager=manager,
        redis_url=redis_url,
        redis_channel=redis_channel,
    )

    heartbeat = HeartbeatMonitor(
        manager=manager,
        interval_seconds=heartbeat_interval,
        timeout_seconds=heartbeat_timeout,
        broadcaster=broadcaster,
    )

    reconnect = ReconnectionManager(
        reconnect_window_seconds=reconnect_window,
    )

    handler = WebSocketHandler(
        manager=manager,
        broadcaster=broadcaster,
        heartbeat=heartbeat,
        reconnect=reconnect,
        jwt_secret=jwt_secret,
        api_keys=api_keys,
        required_roles=required_roles,
        allowed_origins=allowed_origins,
        require_tls=require_tls,
    )
    handler.compression_options = compression_options

    services = WSServices(
        manager=manager,
        broadcaster=broadcaster,
        heartbeat=heartbeat,
        reconnect=reconnect,
        handler=handler,
        job_tenant_resolver=job_tenant_resolver or _default_job_tenant_resolver,
        default_tenant_id=default_tenant_id,
    )

    @app.websocket("/ws/scan-progress")
    async def ws_scan_progress(websocket: WebSocket) -> None:
        await handler.handle_scan_progress(websocket)

    @app.websocket("/ws/job-status")
    async def ws_job_status(websocket: WebSocket) -> None:
        await handler.handle_job_status(websocket)

    @app.websocket("/ws/logs/{job_id}")
    async def ws_job_logs(websocket: WebSocket, job_id: str) -> None:
        await handler.handle_job_logs(websocket, job_id)

    @app.websocket("/ws/dashboard")
    async def ws_dashboard(websocket: WebSocket) -> None:
        await handler.handle_dashboard(websocket)

    @app.websocket("/ws/evasion-telemetry")
    async def ws_evasion_telemetry(websocket: WebSocket) -> None:
        await handler.handle_evasion_telemetry(websocket)

    @app.get("/health/ws")
    async def ws_health() -> Any:
        redis_ok = True
        if broadcaster._redis_enabled and broadcaster._redis_url:
            if broadcaster._redis_client is not None:
                try:
                    await broadcaster._redis_client.ping()
                except Exception:
                    redis_ok = False
            else:
                redis_ok = False
        connections = await manager.get_active_count()
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=200 if redis_ok else 503,
            content={"status": "healthy" if redis_ok else "degraded", "connections": connections},
        )

    @app.get("/metrics")
    async def get_metrics() -> Any:
        from fastapi import Response
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # ------------------------------------------------------------------
    # Admin route protection & audit logging
    # ------------------------------------------------------------------
    effective_admin_roles = (
        admin_required_roles
        if admin_required_roles is not None
        else {"admin"}
    )

    def _resolve_admin_roles(request: Any) -> set[str]:
        """Resolve the roles for a request hitting an admin endpoint."""
        if admin_role_resolver is not None:
            try:
                roles = admin_role_resolver(request)
            except Exception as exc:  # noqa: BLE001
                logger.warning("admin_role_resolver raised: %s", exc)
                roles = None
            if roles is not None:
                return {str(r) for r in roles}
        # Development fallback: read from X-User-Roles header.
        header = request.headers.get("x-user-roles") or ""
        return {part.strip() for part in header.split(",") if part.strip()}

    def _audit_admin(action: str, request: Any, details: dict[str, Any]) -> None:
        actor = "unknown"
        if request is not None:
            client = getattr(request, "client", None)
            actor = (
                f"{getattr(request, 'headers', {}).get('x-user-id', 'unknown')}"
                f"@{client.host if client else 'unknown'}"
            )
        if admin_audit_logger is not None:
            try:
                admin_audit_logger(action, actor, details)
                return
            except Exception as exc:  # noqa: BLE001
                logger.warning("admin_audit_logger raised: %s", exc)
        # Default audit sink: structured warning so it always shows up in
        # centralized log aggregation.
        logger.warning(
            "admin_action action=%s actor=%s details=%s",
            action,
            actor,
            details,
        )

    def _require_admin(request: Any, action: str) -> None:
        from fastapi import HTTPException

        if not effective_admin_roles:
            # Opt-out: no admin roles required. Still emit an audit entry.
            _audit_admin(action, request, {"auth": "disabled"})
            return
        roles = _resolve_admin_roles(request)
        if not roles.intersection(effective_admin_roles):
            _audit_admin(
                action,
                request,
                {"auth": "denied", "roles": sorted(roles)},
            )
            raise HTTPException(
                status_code=403,
                detail=(
                    "Admin privileges required for this endpoint. "
                    f"Required roles: {sorted(effective_admin_roles)}"
                ),
            )
        _audit_admin(action, request, {"auth": "ok", "roles": sorted(roles)})

    @app.get("/admin/websocket/connections")
    async def admin_list_connections(request: Request) -> list[dict[str, Any]]:
        _require_admin(request, "admin_list_connections")
        conns = await manager.get_all_connections()
        return [
            {
                "connection_id": conn.connection_id,
                "user_id": conn.user_id,
                "client_ip": conn.client_ip,
                "connected_at": conn.connected_at,
                "last_activity": conn.last_activity,
                "groups": list(conn.groups),
            }
            for conn in conns
        ]

    @app.delete("/admin/websocket/connections/{connection_id}")
    async def admin_disconnect(request: Request, connection_id: str) -> dict[str, Any]:
        from fastapi import HTTPException
        from starlette.websockets import WebSocketState

        _require_admin(request, "admin_disconnect")

        conn = await manager.get_connection(connection_id)
        if conn is None:
            raise HTTPException(status_code=404, detail="Connection not found")
        if conn.websocket.client_state == WebSocketState.CONNECTED:
            try:
                await conn.websocket.close(code=1001, reason="Forced disconnect by admin")
            except Exception:  # noqa: S110
                pass
        await manager.disconnect(connection_id)
        return {"status": "disconnected", "connection_id": connection_id}

    @app.post("/admin/websocket/broadcast")
    async def admin_broadcast(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
        from fastapi import HTTPException

        from src.websocket_server.protocol import StatusMessage

        _require_admin(request, "admin_broadcast")

        channel = payload.get("channel")
        message_text = payload.get("message")
        if not channel or not message_text:
            raise HTTPException(status_code=400, detail="Missing channel or message")
        msg = StatusMessage(
            job_id="admin", status="announcement", metadata={"message": message_text}
        )
        sent = await broadcaster.broadcast_to_group(channel, msg)
        return {"status": "broadcasted", "channel": channel, "connections_reached": sent}

    @app.get("/admin/websocket/stats")
    async def admin_stats(request: Request) -> dict[str, Any]:
        _require_admin(request, "admin_stats")
        stats = broadcaster.get_stats()
        active_count = await manager.get_active_count()
        stats["active_connections"] = active_count
        return stats

    @app.post("/admin/websocket/config")
    async def admin_config(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
        _require_admin(request, "admin_config")
        if "max_connections_per_user" in payload:
            manager.max_connections_per_user = int(payload["max_connections_per_user"])
        if "max_connections_per_ip" in payload:
            manager.max_connections_per_ip = int(payload["max_connections_per_ip"])
        if "stale_timeout" in payload:
            manager.stale_timeout = float(payload["stale_timeout"])
        if "max_connection_attempts_per_minute" in payload:
            manager.max_connection_attempts_per_minute = int(
                payload["max_connection_attempts_per_minute"]
            )
        return {
            "status": "updated",
            "config": {
                "max_connections_per_user": manager.max_connections_per_user,
                "max_connections_per_ip": manager.max_connections_per_ip,
                "stale_timeout": manager.stale_timeout,
                "max_connection_attempts_per_minute": manager.max_connection_attempts_per_minute,
            },
        }

    @asynccontextmanager
    async def lifespan(app: Any) -> Any:
        await services.start_cleanup_loop(interval=cleanup_interval)
        logger.info("WebSocket services initialized")
        yield
        await services.shutdown()
        logger.info("WebSocket services cleaned up")

    app.router.lifespan_context = lifespan

    # Hook DRL Telemetry
    try:
        from src.core.frontier.drl_evasion import set_telemetry_sink

        class WSTelemetrySink:
            def emit(
                self,
                model_id: str,
                weight_drift: float,
                l2_norm: float,
                action_distribution: list[float],
            ) -> None:
                services.broadcast_telemetry(model_id, weight_drift, l2_norm, action_distribution)

        set_telemetry_sink(WSTelemetrySink())
    except ImportError:
        logger.warning(
            "src.core.frontier.drl_evasion not available, skipping telemetry integration"
        )

    return services


def integrate_with_pipeline_progress(
    services: WSServices,
    job_state_store: dict[str, Any],
    lock: Any = None,
) -> None:
    """Hook WebSocket broadcasting into the pipeline job state system.

    Patches the existing job state tracking to emit WebSocket events
    whenever a job's progress or status changes.

    Args:
        services: WSServices instance from setup_websocket_routes.
        job_state_store: Dict mapping job_id to job state (from src.dashboard).
        lock: Optional threading lock for thread-safe access to job_state_store.
    """

    original_apply_progress: Any = None
    try:
        from src.dashboard.job_state import apply_progress as _orig_apply_progress

        original_apply_progress = _orig_apply_progress
    except ImportError:
        logger.warning("src.dashboard.job_state not available, skipping pipeline integration")
        return

    def _patched_apply_progress(job: dict[str, Any], payload: dict[str, Any]) -> None:
        """Wrapped apply_progress that also broadcasts WebSocket updates."""
        original_apply_progress(job, payload)

        job_id = job.get("id", "")
        if not job_id:
            return

        stage = job.get("stage", "")
        stage_label = job.get("stage_label", "")
        percent = int(job.get("progress_percent", 0) or 0)
        message = job.get("status_message", "")
        target = job.get("hostname", "")
        processed = job.get("stage_processed")
        total = job.get("stage_total")

        services.broadcast_progress(
            job_id=job_id,
            stage=stage,
            stage_label=stage_label,
            percent=percent,
            processed=processed if isinstance(processed, int) else None,
            total=total if isinstance(total, int) else None,
            message=message,
            target=target,
        )

        for log_line in job.get("latest_logs", [])[-3:]:
            services.broadcast_log(
                job_id=job_id,
                line=log_line,
                source="stdout",
                level="warning" if log_line.lower().startswith("warning") else "info",
            )

    from src.dashboard import job_state

    job_state.apply_progress = _patched_apply_progress

    logger.info("Pipeline progress integration active")


def integrate_with_queue_system(
    services: WSServices,
    queue_name: str = "default",
) -> None:
    """Hook WebSocket broadcasting into the queue system for job events.

    Listens for job state transitions in the queue system and broadcasts
    status updates to subscribed WebSocket clients.

    Args:
        services: WSServices instance from setup_websocket_routes.
        queue_name: Queue name to monitor for job events.
    """
    try:
        from src.infrastructure.queue.models import Job, JobState
    except ImportError:
        logger.warning("src.infrastructure.queue.models not available, skipping queue integration")
        return

    async def _on_job_state_change(job: Job, previous_state: JobState) -> None:
        """Broadcast job state transitions from the queue system."""
        job_id = job.id
        target = job.payload.get("target", job.payload.get("base_url", ""))

        services.broadcast_status(
            job_id=job_id,
            status=job.state.value,
            previous_status=previous_state.value,
            progress_percent=_estimate_progress(job),
            error=job.error,
            target=str(target),
            metadata={
                "queue": job.queue_name,
                "retries": job.retries,
                "worker_id": job.worker_id,
            },
        )

    def _estimate_progress(job: Job) -> int:
        """Estimate progress percentage from job state."""
        progress_map = {
            JobState.PENDING: 0,
            JobState.CLAIMED: 2,
            JobState.RUNNING: 10,
            JobState.COMPLETED: 100,
            JobState.FAILED: 0,
            JobState.RETRYING: 5,
            JobState.DEAD_LETTER: 0,
            JobState.CANCELLED: 0,
        }
        return progress_map.get(job.state, 0)

    logger.info("Queue system integration active for queue '%s'", queue_name)

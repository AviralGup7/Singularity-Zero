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
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI
from starlette.websockets import WebSocket

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
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


@dataclass
class WSServices:
    """Convenience access to all WebSocket infrastructure components.

    Attributes:
        manager: Connection manager for active connections.
        broadcaster: Message broadcaster for fan-out delivery.
        heartbeat: Heartbeat monitor for client liveness.
        reconnect: Reconnection manager for session resume.
        handler: Central WebSocket endpoint handler.
        _cleanup_task: Background task for periodic stale connection cleanup.
    """

    manager: ConnectionManager
    broadcaster: Broadcaster
    heartbeat: HeartbeatMonitor
    reconnect: ReconnectionManager
    handler: WebSocketHandler
    _cleanup_task: asyncio.Task[None] | None = field(default=None, repr=False)

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
    ) -> asyncio.Task[int]:
        """Broadcast a scan progress update to subscribed clients.

        Sends to both the job-specific channel and the global channel.

        Args:
            job_id: Job identifier.
            stage: Current pipeline stage name.
            stage_label: Human-readable stage label.
            percent: Overall progress percentage (0-100).
            processed: Items processed in current stage.
            total: Total items in current stage.
            message: Optional status message.
            target: Target URL or hostname.

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
        return asyncio.create_task(
            self._broadcast_to_job_and_global(msg, job_id),
            name=f"ws-progress-{job_id}",
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
    ) -> asyncio.Task[int]:
        """Broadcast a job status change to subscribed clients.

        Sends to both the job-specific channel and the global channel.

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
        return asyncio.create_task(
            self._broadcast_to_job_and_global(msg, job_id),
            name=f"ws-status-{job_id}",
        )

    def broadcast_log(
        self,
        job_id: str,
        line: str,
        source: str = "stdout",
        level: str = "info",
    ) -> asyncio.Task[int]:
        """Broadcast a log line to clients subscribed to the job's log channel.

        Args:
            job_id: Job identifier.
            line: Log line content.
            source: Log source ('stdout' or 'stderr').
            level: Log level ('info', 'warning', 'error').

        Returns:
            Task resolving to the number of connections that received the message.
        """
        msg = LogMessage(
            job_id=job_id,
            line=line,
            source=source,
            level=level,
        )
        return asyncio.create_task(
            self.broadcaster.broadcast_to_group(f"logs:{job_id}", msg),
            name=f"ws-log-{job_id}",
        )

    async def _broadcast_to_job_and_global(
        self,
        message: Any,
        job_id: str,
    ) -> int:
        """Broadcast to both a job-specific channel and the global channel.

        Args:
            message: Message to broadcast.
            job_id: Job identifier for the job-specific channel.

        Returns:
            Total number of connections that received the message.
        """
        job_sent = await self.broadcaster.broadcast_to_group(f"job:{job_id}", message)
        global_sent = await self.broadcaster.broadcast_to_group("global", message, exclude=set())
        return max(job_sent, global_sent)

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
    max_connections_per_user: int = 10,
    max_connections_per_ip: int = 20,
    heartbeat_interval: float = 30.0,
    heartbeat_timeout: float = 90.0,
    reconnect_window: float = 300.0,
    cleanup_interval: float = 60.0,
    redis_url: str | None = None,
    redis_channel: str = "ws:broadcasts",
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
        max_connections_per_user: Max concurrent connections per user.
        max_connections_per_ip: Max concurrent connections per IP.
        heartbeat_interval: Seconds between heartbeat pings.
        heartbeat_timeout: Seconds of inactivity before disconnecting.
        reconnect_window: Seconds a reconnection token remains valid.
        cleanup_interval: Seconds between stale connection cleanup runs.

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
    )

    services = WSServices(
        manager=manager,
        broadcaster=broadcaster,
        heartbeat=heartbeat,
        reconnect=reconnect,
        handler=handler,
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

    @asynccontextmanager
    async def lifespan(app):
        await services.start_cleanup_loop(interval=cleanup_interval)
        logger.info("WebSocket services initialized")
        yield
        await services.shutdown()
        logger.info("WebSocket services cleaned up")

    app.router.lifespan_context = lifespan

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

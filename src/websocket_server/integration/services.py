"""WSServices — central dataclass holding all WebSocket infrastructure."""

from __future__ import annotations

import asyncio
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.broadcaster import Broadcaster
from src.websocket_server.handlers import WebSocketHandler
from src.websocket_server.heartbeat import HeartbeatMonitor
from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import LogMessage, ProgressMessage, StatusMessage
from src.websocket_server.reconnect import ReconnectionManager

logger = get_pipeline_logger(__name__)


def _default_job_tenant_resolver(job_id: str) -> str | None:
    """Best-effort default job-to-tenant resolver."""
    try:
        from src.dashboard import job_state as dashboard_job_state
    except (ImportError, ModuleNotFoundError):
        return None
    get_job = getattr(dashboard_job_state, "get_job", None)
    if not callable(get_job):
        return None
    try:
        job = get_job(job_id)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        logger.debug("Job lookup failed for %s: %s", job_id, exc)
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


class WSServices:
    """Central dataclass holding all WebSocket infrastructure.

    All broadcast convenience methods live here. The class is
    instantiated once by ``setup_websocket_routes`` and shared
    across all route handlers via FastAPI dependency injection.
    """

    def __init__(
        self,
        manager: ConnectionManager,
        broadcaster: Broadcaster,
        heartbeat: HeartbeatMonitor,
        handler: WebSocketHandler,
        reconnect: ReconnectionManager,
        *,
        job_tenant_resolver: Any | None = None,
    ) -> None:
        self.manager = manager
        self.broadcaster = broadcaster
        self.heartbeat = heartbeat
        self.handler = handler
        self.reconnect = reconnect
        self._cleanup_task: asyncio.Task[None] | None = None
        self._tenant_resolver = job_tenant_resolver or _default_job_tenant_resolver

    def _tenant_for_job(self, job_id: str) -> str | None:
        try:
            return self._tenant_resolver(job_id)
        except Exception as exc:
            logger.debug("Tenant resolution failed for job %s: %s", job_id, exc)
            return None

    @staticmethod
    def _log_task_exception(task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.debug("Background task failed: %s", exc)

    def broadcast_progress(
        self,
        job_id: str,
        stage: str,
        percent: int,
        *,
        detail: str = "",
        status: str = "running",
    ) -> None:
        from src.core.utils.async_bridge import run_async_in_sync_context

        msg = ProgressMessage(
            job_id=job_id,
            stage=stage,
            percent=percent,
            detail=detail,
            status=status,
        )
        run_async_in_sync_context(self._broadcast_to_job_and_tenant(job_id, msg))

    def broadcast_telemetry(
        self,
        job_id: str,
        *,
        data: dict[str, Any],
    ) -> None:
        try:
            from src.core.utils.async_bridge import run_async_in_sync_context
            from src.websocket_server.protocol import TelemetryMessage

            msg = TelemetryMessage(job_id=job_id, data=data)
            run_async_in_sync_context(self._broadcast_to_job_and_tenant(job_id, msg))
        except Exception as exc:
            logger.debug("Telemetry broadcast failed for %s: %s", job_id, exc)

    def broadcast_status(
        self,
        job_id: str,
        status: str,
        *,
        detail: str = "",
        exit_code: int | None = None,
    ) -> None:
        from src.core.utils.async_bridge import run_async_in_sync_context

        msg = StatusMessage(
            job_id=job_id,
            status=status,
            detail=detail,
            exit_code=exit_code,
        )
        run_async_in_sync_context(self._broadcast_to_job_and_tenant(job_id, msg))

    def broadcast_log(
        self,
        job_id: str,
        line: str,
        *,
        source: str = "stdout",
    ) -> None:
        from src.core.utils.async_bridge import run_async_in_sync_context

        msg = LogMessage(
            job_id=job_id,
            line=line,
            source=source,
        )
        run_async_in_sync_context(self._broadcast_to_job_and_tenant(job_id, msg))

    async def _broadcast_to_job_and_tenant(self, job_id: str, msg: Any) -> int:
        count = await self.broadcaster.broadcast_to_group(f"job:{job_id}", msg)
        tenant = self._tenant_for_job(job_id)
        if tenant:
            count += await self.broadcaster.broadcast_to_group(f"global:{tenant}", msg)
        return count

    async def _broadcast_to_job_and_global(self, job_id: str, msg: Any) -> int:
        return await self._broadcast_to_job_and_tenant(job_id, msg)

    def start_cleanup_loop(self, interval: float = 30.0) -> None:
        async def _cleanup() -> None:
            while True:
                try:
                    await asyncio.sleep(interval)
                    self.manager.cleanup_stale()
                    self.reconnect.cleanup_expired()
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.debug("Cleanup loop error: %s", exc)

        self._cleanup_task = asyncio.create_task(_cleanup())
        self._cleanup_task.add_done_callback(self._log_task_exception)

    def shutdown(self) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
        from src.core.utils.async_bridge import run_async_in_sync_context

        try:
            run_async_in_sync_context(self.heartbeat.stop_all())
        except Exception as exc:
            logger.debug("Failed to stop heartbeat monitor: %s", exc)
        try:
            run_async_in_sync_context(self.manager.close_all())
        except Exception as exc:
            logger.debug("Failed to close connection manager: %s", exc)

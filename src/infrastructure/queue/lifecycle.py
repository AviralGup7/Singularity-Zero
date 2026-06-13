"""Worker lifecycle, registration, heartbeat, and shutdown.

Provides the Worker class lifecycle management (start, heartbeat, shutdown),
configurable concurrency, health reporting, and automatic reconnection handling.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import time
from typing import Any

from src.core.contracts.health import (
    CorrectionEvent,
    CorrectiveAction,
    HealthComponent,
    HealthFinding,
)
from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.checkpoint import DistributedCheckpointStore
from src.infrastructure.queue.models import WorkerInfo

logger = get_pipeline_logger(__name__)


class WorkerLifecycleMixin:
    """Mixin owning worker initialization, lifecycle state, health, cleanup,
    and stop/restart hooks."""

    def __init__(
        self,
        worker_id: str,
        queue: Any,
        handler: Any | None = None,
        concurrency: int = 1,
        poll_interval: float = 1.0,
        heartbeat_interval: float = 15.0,
        shutdown_timeout: float = 30.0,
        capabilities: list[str] | None = None,
        distributed_store: DistributedCheckpointStore | None = None,
        discovery: Any | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.queue = queue
        self.handler = handler
        self.concurrency = max(1, concurrency)
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.shutdown_timeout = shutdown_timeout
        self.capabilities = capabilities or []
        self.distributed_store = distributed_store
        self.discovery = discovery

        self._info = WorkerInfo(
            id=worker_id,
            hostname=socket.gethostname(),
            pid=os.getpid(),
            status="idle",
            concurrency=self.concurrency,
            capabilities=self.capabilities,
            metadata={"accepts_concurrent_claims": self.concurrency > 1},
        )
        self._running = False
        self._shutdown_requested = False
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._active_tasks_lock = asyncio.Lock()
        self._restart_requested = False

    @property
    def info(self) -> WorkerInfo:
        return self._info

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_shutdown_requested(self) -> bool:
        return self._shutdown_requested

    def _setup_signal_handlers(self) -> None:
        def signal_handler(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info("Received %s, initiating graceful shutdown", sig_name)
            self._shutdown_requested = True

        try:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        except (ValueError, OSError):
            logger.debug("Cannot set signal handlers (not in main thread)")

    async def _register(self) -> None:
        self._info.started_at = time.time()
        self._info.last_heartbeat = time.time()
        self._info.status = "idle"

        worker_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}"
        self.queue.redis.execute_command("HSET", worker_key, mapping=self._info.to_redis_hash())
        self.queue.redis.execute_command(
            "SADD", f"queue:{self.queue.queue_name}:workers", self.worker_id
        )

        if self.capabilities:
            caps_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}:capabilities"
            for cap in self.capabilities:
                self.queue.redis.execute_command("SADD", caps_key, cap)
            self.queue.redis.execute_command("EXPIRE", caps_key, int(self.heartbeat_interval * 5))

        if self.discovery:
            self.discovery.register()
            self.discovery.start_discovery()

        self._setup_signal_handlers()
        logger.info(
            "Worker %s registered (hostname=%s, pid=%d, concurrency=%d, capabilities=%s)",
            self.worker_id,
            self._info.hostname,
            self._info.pid,
            self.concurrency,
            self.capabilities,
        )

    async def _heartbeat(self) -> None:
        while self._running and not self._shutdown_requested:
            try:
                self._info.last_heartbeat = time.time()
                worker_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}"
                self.queue.redis.execute_command(
                    "HSET", worker_key, mapping=self._info.to_redis_hash()
                )
                self.queue.redis.execute_command(
                    "EXPIRE", worker_key, int(self.heartbeat_interval * 5)
                )
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Heartbeat failed: %s", exc)
                await asyncio.sleep(self.heartbeat_interval)

    async def _cleanup(self) -> None:
        self._info.status = "shutting_down"

        active_jobs = list(self._info.active_jobs)
        for job_id in active_jobs:
            try:
                await self.queue.release_lease(job_id, self.worker_id)
                logger.info("Released lease for job %s during shutdown", job_id)
            except Exception as exc:
                logger.warning("Failed to release lease for job %s: %s", job_id, exc)

        self._info.active_jobs.clear()
        self._info.status = "dead"

        worker_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}"
        self.queue.redis.execute_command("HSET", worker_key, mapping=self._info.to_redis_hash())
        self.queue.redis.execute_command(
            "SREM", f"queue:{self.queue.queue_name}:workers", self.worker_id
        )

        if self.discovery:
            self.discovery.shutdown()

        async with self._active_tasks_lock:
            tasks_snapshot = list(self._active_tasks)
        if tasks_snapshot:
            logger.info("Waiting for %d active tasks to complete", len(tasks_snapshot))
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks_snapshot, return_exceptions=True),
                    timeout=self.shutdown_timeout,
                )
            except TimeoutError:
                logger.warning("Shutdown timeout reached, cancelling remaining tasks")
                for task in tasks_snapshot:
                    task.cancel()

    async def stop(self) -> None:
        if not self._running:
            return
        logger.info("Stopping worker %s...", self.worker_id)
        self._shutdown_requested = True

    async def restart_from_health_finding(
        self, finding: HealthFinding | None = None
    ) -> CorrectionEvent:
        self._restart_requested = True
        await self.stop()
        return CorrectionEvent(
            finding_id=finding.finding_id if finding else "",
            action=CorrectiveAction.RESTART_WORKER,
            success=True,
            message=f"Worker {self.worker_id} restart requested",
            component=HealthComponent.WORKER,
            details={"worker_id": self.worker_id, "labels": finding.labels if finding else {}},
        )

    def get_health(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "status": self._info.status,
            "is_running": self._running,
            "shutdown_requested": self._shutdown_requested,
            "restart_requested": self._restart_requested,
            "active_jobs": len(self._info.active_jobs),
            "concurrency": self.concurrency,
            "total_processed": self._info.total_processed,
            "total_failed": self._info.total_failed,
            "uptime_seconds": round(time.time() - self._info.started_at, 2),
            "last_heartbeat": self._info.last_heartbeat,
            "hostname": self._info.hostname,
            "pid": self._info.pid,
        }

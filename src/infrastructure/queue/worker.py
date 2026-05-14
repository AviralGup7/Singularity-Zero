"""Worker implementation for processing jobs from the queue.

Provides the Worker class with graceful lifecycle management (start,
heartbeat, shutdown), job processing with error isolation, configurable
concurrency, health reporting, and automatic reconnection handling.
"""

import asyncio
import os
import signal
import socket
import threading
import time
import traceback
from collections.abc import Callable
from typing import Any

from src.infrastructure.checkpoint import DistributedCheckpointStore
from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.job_queue import JobQueue
from src.infrastructure.queue.models import Job, WorkerInfo
from src.infrastructure.queue.redis_client import RedisClient
from src.core.frontier.tracing_manager import get_tracing_manager

logger = get_pipeline_logger(__name__)


class Worker:
    """Queue worker that processes jobs with graceful lifecycle management.

    The worker manages its own lifecycle including registration with the
    queue, periodic heartbeats, job polling and processing, error isolation,
    and graceful shutdown on SIGINT/SIGTERM signals.

    Multiple workers can run concurrently, each with configurable concurrency
    for parallel job processing within a single worker process.

    Attributes:
        worker_id: Unique identifier for this worker.
        queue: JobQueue instance to pull jobs from.
        handler: Callable that processes individual jobs.
        concurrency: Maximum number of jobs to process simultaneously.
        poll_interval: Seconds to wait between job polling attempts.
        heartbeat_interval: Seconds between heartbeat signals.
        shutdown_timeout: Seconds to wait for running jobs during shutdown.
        _info: WorkerInfo instance tracking worker state.
        _running: Whether the worker is currently running.
        _shutdown_requested: Whether shutdown has been requested.
        _active_tasks: Set of currently running asyncio tasks.
        _lock: Thread lock for state synchronization.
    """

    def __init__(
        self,
        worker_id: str,
        queue: JobQueue,
        handler: Callable[[Job], Any] | None = None,
        concurrency: int = 1,
        poll_interval: float = 1.0,
        heartbeat_interval: float = 15.0,
        shutdown_timeout: float = 30.0,
        capabilities: list[str] | None = None,
        distributed_store: DistributedCheckpointStore | None = None,
        discovery: Any | None = None,
    ) -> None:
        """Initialize the worker.

        Args:
            worker_id: Unique identifier for this worker.
            queue: JobQueue instance to pull jobs from.
            handler: Callable that processes individual jobs. Accepts a Job
                     and returns the result dict. If None, uses queue's
                     registered handlers based on job type.
            concurrency: Maximum simultaneous jobs for this worker.
            poll_interval: Seconds between job polling attempts.
            heartbeat_interval: Seconds between heartbeat signals.
            shutdown_timeout: Seconds to wait for running jobs during shutdown.
            capabilities: List of capability tags (e.g., ["browser", "heavy_compute"]).
            distributed_store: Optional Redis-backed store for checkpoint failover.
            discovery: Optional mDNS discovery service.
        """
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
        )
        self._running = False
        self._shutdown_requested = False
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def info(self) -> WorkerInfo:
        """Get the current worker information.

        Returns:
            WorkerInfo instance with current worker state.
        """
        return self._info

    @property
    def is_running(self) -> bool:
        """Check if the worker is currently running.

        Returns:
            True if the worker has been started and not yet stopped.
        """
        return self._running

    @property
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested.

        Returns:
            True if shutdown was requested via signal or method call.
        """
        return self._shutdown_requested

    def _setup_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown on SIGINT/SIGTERM."""

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
        """Register this worker with the queue system.

        Creates the worker info entry in Redis and sets up signal handlers.
        Also registers capabilities for resource-aware scheduling.
        """
        self._info.started_at = time.time()
        self._info.last_heartbeat = time.time()
        self._info.status = "idle"

        worker_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}"
        self.queue.redis.execute_command("HSET", worker_key, mapping=self._info.to_redis_hash())
        self.queue.redis.execute_command(
            "SADD", f"queue:{self.queue.queue_name}:workers", self.worker_id
        )

        # Register capabilities for resource-aware scheduling
        if self.capabilities:
            caps_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}:capabilities"
            for cap in self.capabilities:
                self.queue.redis.execute_command("SADD", caps_key, cap)
            self.queue.redis.execute_command("EXPIRE", caps_key, int(self.heartbeat_interval * 5))

        # Register with mDNS if discovery is enabled
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
        """Send periodic heartbeat to indicate worker liveness.

        Updates the worker's last_heartbeat timestamp in Redis and
        refreshes the worker info entry.
        """
        while self._running and not self._shutdown_requested:
            try:
                self._info.last_heartbeat = time.time()
                worker_key = f"queue:{self.queue.queue_name}:worker:{self.worker_id}"
                self.queue.redis.execute_command(
                    "HSET", worker_key, mapping=self._info.to_redis_hash()
                )
                # EXPIRE requires an integer, not a string
                self.queue.redis.execute_command(
                    "EXPIRE", worker_key, int(self.heartbeat_interval * 5)
                )
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Heartbeat failed: %s", exc)
                await asyncio.sleep(self.heartbeat_interval)

    async def _process_job(self, job: Job) -> None:
        """Process a single job with error isolation.

        Handles the full job lifecycle: marking as running, executing the
        handler, and marking as completed or failed based on the outcome.

        Args:
            job: Job instance to process.
        """
        job.mark_running()
        self._info.status = "busy"
        self._info.active_jobs.append(job.id)

        job_key = f"queue:{self.queue.queue_name}:job:{job.id}"
        self.queue.redis.execute_command(
            "HSET",
            job_key,
            "state",
            "running",
            "started_at",
            str(time.time()),
            "worker_id",
            self.worker_id,
        )

        try:
            handler = self.handler or self.queue.get_handler(job.type)
            if handler is None:
                raise ValueError(f"No handler registered for job type: {job.type}")

            # Strict runtime validation to ensure payload is a serialized TaskEnvelope
            if not isinstance(job.payload, dict) or not job.payload.get("schema_version"):
                error_msg = (
                    f"Job {job.id} rejected: payload is not a valid TaskEnvelope. "
                    "All queue payloads must be TaskEnvelope instances."
                )
                logger.error(error_msg)
                await self.queue.fail_job(job.id, self.worker_id, error_msg)
                return

            envelope = job.as_task_envelope()
            handler_input: Any = envelope

            if not isinstance(envelope.type, str) or not envelope.type:
                logger.error(
                    "Job %s rejected: invalid TaskEnvelope type '%s' (missing or non-string). "
                    "All queue payloads must be TaskEnvelope instances.",
                    job.id,
                    getattr(envelope, "type", None),
                )
                await self.queue.fail_job(
                    job.id,
                    self.worker_id,
                    "Invalid TaskEnvelope: missing or empty type field",
                )
                return

            tracer = get_tracing_manager()
            parent_headers = tracer.extract_task_headers(envelope)
            with tracer.start_span(
                f"queue.worker.{envelope.type}",
                parent_headers=parent_headers,
                attributes={
                    "stage_name": envelope.type,
                    "job_id": job.id,
                    "queue_name": self.queue.queue_name,
                    "worker_id": self.worker_id,
                    "target_count": 1,
                    "scope_size": 0,
                },
            ) as span:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(handler_input)
                else:
                    result = await asyncio.to_thread(handler, handler_input)
                span.set_attribute("status", "OK")

            await self.queue.complete_job(job.id, self.worker_id, result)
            self._info.total_processed += 1
            logger.info("Job %s completed successfully (type=%s)", job.id, job.type)

        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
            logger.error("Job %s failed (type=%s): %s", job.id, job.type, exc)

            success, outcome = await self.queue.fail_job(job.id, self.worker_id, error_msg)

            if outcome == "dead_letter":
                logger.warning(
                    "Job %s moved to dead-letter queue after %d retries",
                    job.id,
                    job.retries,
                )
            self._info.total_failed += 1

        finally:
            if job.id in self._info.active_jobs:
                self._info.active_jobs.remove(job.id)

            if len(self._info.active_jobs) == 0:
                self._info.status = "idle"

    async def _poll_and_process(self) -> None:
        """Continuously poll for jobs and process them.

        Main processing loop that claims jobs from the queue, processes
        them, and respects concurrency limits. Uses resource-aware
        scheduling if the queue supports it.
        """
        while self._running and not self._shutdown_requested:
            try:
                active_count = len(self._info.active_jobs)
                if active_count >= self.concurrency:
                    await asyncio.sleep(self.poll_interval)
                    continue

                # Use resource-aware job selection if available
                if hasattr(self.queue, 'get_next_job_for_worker'):
                    job = await self.queue.get_next_job_for_worker(self.worker_id)
                else:
                    job = await self.queue.claim_job(self.worker_id)

                if job is None:
                    await asyncio.sleep(self.poll_interval)
                    continue

                task = asyncio.create_task(self._process_job(job))
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Poll loop error: %s", exc)
                await asyncio.sleep(self.poll_interval)

    async def _cleanup(self) -> None:
        """Clean up worker resources during shutdown.

        Releases any active job leases and updates worker status.
        """
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

        if self._active_tasks:
            logger.info("Waiting for %d active tasks to complete", len(self._active_tasks))
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._active_tasks, return_exceptions=True),
                    timeout=self.shutdown_timeout,
                )
            except TimeoutError:
                logger.warning("Shutdown timeout reached, cancelling remaining tasks")
                for task in self._active_tasks:
                    task.cancel()

    async def _handle_stale_checkpoints(self) -> None:
        """Check for checkpoints owned by dead workers and take them over.

        This enables cross-node checkpoint handoff for zero data loss.
        """
        if not self.distributed_store:
            return

        try:
            # Get all workers from the queue
            workers_key = f"queue:{self.queue.queue_name}:workers"
            alive_workers_data = self.queue.redis.execute_command("SMEMBERS", workers_key)
            alive_workers = set()
            if alive_workers_data:
                for w in alive_workers_data:
                    alive_workers.add(w.decode("utf-8") if isinstance(w, bytes) else w)

            # Find dead worker checkpoints
            dead_checkpoints = await self.distributed_store.list_dead_worker_checkpoints(
                list(alive_workers)
            )

            for run_id, dead_worker_id in dead_checkpoints:
                logger.warning(
                    "Found checkpoint %s owned by dead worker %s",
                    run_id,
                    dead_worker_id,
                )
                # Try to take over the checkpoint
                success = await self.distributed_store.take_ownership(
                    run_id, self.worker_id
                )
                if success:
                    logger.info(
                        "Took ownership of checkpoint %s from dead worker %s",
                        run_id,
                        dead_worker_id,
                    )
                    # Here you would resume the pipeline from the checkpoint
                    # await self._resume_pipeline(run_id)
                else:
                    logger.warning(
                        "Failed to take ownership of checkpoint %s", run_id
                    )
        except Exception as exc:
            logger.error("Error handling stale checkpoints: %s", exc)

    async def start(self) -> None:
        """Start the worker and begin processing jobs.

        Registers the worker, starts the heartbeat loop, checks for
        stale checkpoints to take over, and enters the main poll-and-process
        loop. Blocks until shutdown is requested.
        """
        if self._running:
            logger.warning("Worker %s is already running", self.worker_id)
            return

        self._running = True
        self._shutdown_requested = False
        self._loop = asyncio.get_running_loop()

        await self._register()

        # Check for stale checkpoints to take over
        await self._handle_stale_checkpoints()

        heartbeat_task = asyncio.create_task(self._heartbeat())

        try:
            await self._poll_and_process()
        except asyncio.CancelledError:
            pass
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

            await self._cleanup()
            self._running = False
            logger.info(
                "Worker %s stopped (processed=%d, failed=%d)",
                self.worker_id,
                self._info.total_processed,
                self._info.total_failed,
            )

    async def stop(self) -> None:
        """Request graceful shutdown of the worker.

        Signals the worker to stop accepting new jobs and waits for
        active jobs to complete or the shutdown timeout to expire.
        """
        if not self._running:
            return

        logger.info("Stopping worker %s...", self.worker_id)
        self._shutdown_requested = True

    def get_health(self) -> dict[str, Any]:
        """Get the current health status of the worker.

        Returns:
            Dict with worker health information including status,
            active job count, and processing statistics.
        """
        return {
            "worker_id": self.worker_id,
            "status": self._info.status,
            "is_running": self._running,
            "shutdown_requested": self._shutdown_requested,
            "active_jobs": len(self._info.active_jobs),
            "concurrency": self.concurrency,
            "total_processed": self._info.total_processed,
            "total_failed": self._info.total_failed,
            "uptime_seconds": round(time.time() - self._info.started_at, 2),
            "last_heartbeat": self._info.last_heartbeat,
            "hostname": self._info.hostname,
            "pid": self._info.pid,
        }


def main(argv: list[str] | None = None) -> None:
    """Entry point for the queue worker CLI."""
    import argparse
    import uuid

    parser = argparse.ArgumentParser(description="Security Pipeline Queue Worker")
    parser.add_argument("--queue", default="security-pipeline", help="Queue name")
    parser.add_argument("--concurrency", type=int, default=2, help="Worker concurrency")
    parser.add_argument(
        "--max-jobs", type=int, default=100, help="Maximum jobs to process (0 for unlimited)"
    )
    parser.add_argument("--worker-id", default=None, help="Worker ID (defaults to UUID)")
    parser.add_argument(
        "--capabilities",
        nargs="*",
        default=[],
        help="Worker capabilities (e.g., browser, heavy_compute)"
    )
    parser.add_argument(
        "--enable-checkpoint-replication",
        action="store_true",
        help="Enable checkpoint replication via Redis"
    )
    parser.add_argument(
        "--enable-discovery",
        action="store_true",
        help="Enable automatic peer discovery via mDNS"
    )
    parser.add_argument(
        "--discovery-port",
        type=int,
        default=8008,
        help="Port for mDNS discovery"
    )
    args = parser.parse_args(argv)

    queue = JobQueue(RedisClient(), args.queue)
    worker_id = args.worker_id or str(uuid.uuid4())

    # Create distributed store if checkpoint replication is enabled
    distributed_store = None
    if args.enable_checkpoint_replication:
        from src.infrastructure.checkpoint import DistributedCheckpointStore
        distributed_store = DistributedCheckpointStore(RedisClient(), worker_id)

    # Create discovery service if enabled
    discovery = None
    if args.enable_discovery:
        from src.infrastructure.discovery import WorkerDiscovery
        discovery = WorkerDiscovery(
            worker_id=worker_id,
            port=args.discovery_port,
            metadata={
                "hostname": socket.gethostname(),
                "capabilities": ",".join(args.capabilities),
            }
        )

    worker = Worker(
        worker_id=worker_id,
        queue=queue,
        concurrency=args.concurrency,
        capabilities=args.capabilities,
        distributed_store=distributed_store,
        discovery=discovery,
    )

    async def _run() -> None:
        try:
            await worker.start()
        finally:
            await worker.stop()

    asyncio.run(_run())


if __name__ == "__main__":
    main()

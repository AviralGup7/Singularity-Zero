"""Backward-compatible shim for the split worker module.

All public classes and functions are re-exported from their new locations.
This file will be removed once all downstream imports are migrated.
"""

from src.infrastructure.queue.execution_loop import WorkerExecutionLoopMixin
from src.infrastructure.queue.lifecycle import WorkerLifecycleMixin
from src.infrastructure.queue.task_handlers import WorkerTaskHandlersMixin


class Worker(
    WorkerLifecycleMixin,
    WorkerExecutionLoopMixin,
    WorkerTaskHandlersMixin,
):
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

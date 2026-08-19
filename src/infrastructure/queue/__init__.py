"""Production-grade distributed job queue system.

Provides Redis-backed job queue with in-memory fallback, priority scheduling,
configurable retry policies, dead-letter queue handling, and worker lifecycle
management for the cyber security test pipeline.

Usage:
    from src.infrastructure.queue import JobQueue, Worker, QueueConfig, JobState
    from src.core.contracts.task_envelope import TaskEnvelope

    config = QueueConfig(redis_url="redis://localhost:6379")
    queue = JobQueue(config)
    job_id = await queue.enqueue(TaskEnvelope(type="pipeline_scan", payload={"target": "example.com"}), priority=5)
"""

import os
import threading

from src.infrastructure.queue.base_worker import BaseWorker
from src.infrastructure.queue.coordinator import SweepReport, WorkerCoordinator
from src.infrastructure.queue.job_queue import JobQueue
from src.infrastructure.queue.models import (
    Job,
    JobState,
    QueueConfig,
    WorkerInfo,
)
from src.infrastructure.queue.models import (
    QueueConfig as QueueConfigModel,
)
from src.infrastructure.queue.plugin_handler_bridge import (
    register_all_plugin_handlers,
    resolve_handler_for_job_type,
)
from src.infrastructure.queue.redis_client import RedisClient
from src.infrastructure.queue.retry_policy import RetryPolicy
from src.infrastructure.queue.worker import Worker
from src.infrastructure.queue.worker_phase import WorkerPhase, normalize_phase

_job_queue: JobQueue | None = None
_job_queue_lock = threading.Lock()


def get_job_queue() -> JobQueue:
    """Return the process-wide JobQueue singleton (in-memory if Redis is unset)."""
    global _job_queue
    if _job_queue is not None:
        return _job_queue
    with _job_queue_lock:
        if _job_queue is None:
            redis_url = os.environ.get("REDIS_URL")
            client = RedisClient(url=redis_url)
            queue_name = os.environ.get("WORKER_QUEUE", "security-pipeline")
            namespace = os.environ.get("QUEUE_NAMESPACE", "queue")
            _job_queue = JobQueue(client, queue_name=queue_name, namespace=namespace)
        return _job_queue


def set_job_queue(queue: JobQueue | None) -> None:
    """Replace the process-wide JobQueue (used by tests and app startup)."""
    global _job_queue
    with _job_queue_lock:
        _job_queue = queue


__all__ = [
    "BaseWorker",
    "Job",
    "JobQueue",
    "JobState",
    "QueueConfig",
    "QueueConfigModel",
    "RedisClient",
    "RetryPolicy",
    "SweepReport",
    "Worker",
    "WorkerCoordinator",
    "WorkerInfo",
    "WorkerPhase",
    "get_job_queue",
    "normalize_phase",
    "register_all_plugin_handlers",
    "resolve_handler_for_job_type",
    "set_job_queue",
]

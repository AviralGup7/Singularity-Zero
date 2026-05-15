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
from src.infrastructure.queue.redis_client import RedisClient
from src.infrastructure.queue.worker import Worker

__all__ = [
    "Job",
    "JobQueue",
    "JobState",
    "QueueConfig",
    "QueueConfigModel",
    "RedisClient",
    "Worker",
    "WorkerInfo",
]

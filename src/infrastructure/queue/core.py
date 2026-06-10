"""Core job queue implementation with priority scheduling and atomic state transitions.

Provides the core JobQueue class with job enqueue/dequeue, priority-based
scheduling, atomic state transitions via Redis Lua scripts, lease management,
dead-letter queue handling, and configurable retry policies.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from src.core.contracts.task_envelope import TaskEnvelope
from src.core.frontier.tracing_manager import get_tracing_manager
from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.lua_scripts import (
    CLAIM_JOB_SCRIPT,
    COMPLETE_JOB_SCRIPT,
    ENQUEUE_SCRIPT,
    FAIL_JOB_SCRIPT,
    RELEASE_LEASE_SCRIPT,
)
from src.infrastructure.queue.models import Job
from src.infrastructure.queue.redis_client import RedisClient
from src.infrastructure.queue.retry_policy import RetryPolicy
from src.infrastructure.scheduling.resource_aware import ResourceAwareScheduler

logger = get_pipeline_logger(__name__)


class JobQueueCore:
    def __init__(
        self,
        redis_client: RedisClient,
        queue_name: str = "default",
        retry_policy: RetryPolicy | None = None,
        lease_seconds: float = 300.0,
        dead_letter_queue_name: str = "dead_letter",
        enable_scheduler: bool = True,
        namespace: str = "queue",
    ) -> None:
        self.redis = redis_client
        self.queue_name = queue_name
        self.retry_policy = retry_policy or RetryPolicy()
        self.lease_seconds = lease_seconds
        self.dead_letter_queue_name = dead_letter_queue_name
        self._handlers: dict[str, Callable[[Job], Any]] = {}
        self._scripts_registered = False
        self._namespace = namespace
        self.scheduler = ResourceAwareScheduler() if enable_scheduler else None
        self._register_scripts()

    def _key(self, suffix: str) -> str:
        return f"{self._namespace}:{self.queue_name}:{suffix}"

    def _job_key(self, job_id: str) -> str:
        return f"{self._namespace}:{self.queue_name}:job:{job_id}"

    def _register_scripts(self) -> None:
        if self._scripts_registered:
            return
        self.redis.register_script("claim_job", CLAIM_JOB_SCRIPT)
        self.redis.register_script("complete_job", COMPLETE_JOB_SCRIPT)
        self.redis.register_script("fail_job", FAIL_JOB_SCRIPT)
        self.redis.register_script("release_lease", RELEASE_LEASE_SCRIPT)
        self.redis.register_script("enqueue", ENQUEUE_SCRIPT)
        self._scripts_registered = True

    async def enqueue(
        self,
        task: TaskEnvelope,
        *,
        priority: int | None = None,
        max_retries: int | None = None,
        job_id: str | None = None,
    ) -> str:
        task = get_tracing_manager().inject_task_context(task)
        job = Job.from_task_envelope(
            task,
            queue_name=self.queue_name,
            priority=priority if priority is not None else 5,
            max_retries=max_retries if max_retries is not None else self.retry_policy.max_retries,
            job_id=job_id,
        )
        job.compute_bid()

        job_hash = job.to_redis_hash()
        hash_args: list[str] = []
        for k, v in job_hash.items():
            hash_args.append(k)
            hash_args.append(v)

        hash_args_json = json.dumps(hash_args)
        if len(hash_args_json) > 1024 * 1024:
            raise ValueError(
                f"Task envelope too large for queue (size: {len(hash_args_json)} bytes)"
            )

        await asyncio.to_thread(
            self.redis.execute_script,
            "enqueue",
            keys=[self._job_key(job.id), self._key("queue")],
            args=[
                str(job.priority),
                job.id,
                str(job.created_at),
                hash_args_json,
                str(job.bid_score),
            ],
        )
        logger.info(
            "Enqueued task job %s (type=%s, correlation_id=%s)",
            job.id,
            task.type,
            task.correlation_id,
        )
        return job.id

    def register_handler(self, job_type: str, handler: Callable[[Job], Any]) -> None:
        self._handlers[job_type] = handler
        logger.info("Registered handler for job type: %s", job_type)

    def get_handler(self, job_type: str) -> Callable[[Job], Any] | None:
        return self._handlers.get(job_type)

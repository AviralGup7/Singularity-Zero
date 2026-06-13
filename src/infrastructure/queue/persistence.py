"""Job persistence and delayed-queue operations for the job queue."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.core import JobQueueCore
from src.infrastructure.queue.models import Job, JobState
from src.core.contracts.health import HealthComponent, HealthMetric, HealthStatus

logger = get_pipeline_logger(__name__)


class JobQueuePersistenceMixin(JobQueueCore):
    async def get_job(self, job_id: str) -> Job | None:
        job_data = await asyncio.to_thread(
            self.redis.execute_command, "HGETALL", self._job_key(job_id)
        )
        if not job_data:
            return None
        return Job.from_redis_hash(job_data)

    async def get_queue_length(self) -> int:
        result = await asyncio.to_thread(self.redis.execute_command, "ZCARD", self._key("queue"))
        return int(result) if result else 0

    async def get_dead_letter_count(self) -> int:
        result = await asyncio.to_thread(
            self.redis.execute_command, "ZCARD", self._key(self.dead_letter_queue_name)
        )
        return int(result) if result else 0

    async def list_dead_letters(self, limit: int = 50) -> list[Job]:
        members = await asyncio.to_thread(
            self.redis.execute_command,
            "ZRANGEBYSCORE",
            self._key(self.dead_letter_queue_name),
            "-inf",
            "+inf",
            "LIMIT",
            "0",
            str(limit),
        )

        jobs: list[Job] = []
        if not members:
            return jobs

        batch_commands = []
        for member in members:
            job_key_str = member.decode("utf-8") if isinstance(member, bytes) else member
            job_id = job_key_str.split(":")[-1]
            batch_commands.append(("HGETALL", [self._job_key(job_id)]))

        batch_results = await asyncio.to_thread(self.redis.execute_batch, batch_commands)
        for job_data in batch_results:
            if job_data:
                try:
                    job = Job.from_redis_hash(job_data)
                    jobs.append(job)
                except Exception as exc:
                    logger.warning("Failed to deserialize job from batch result: %s", exc)

        return jobs

    async def retry_dead_letter(self, job_id: str) -> bool:
        job = await self.get_job(job_id)
        if job is None or job.state != JobState.DEAD_LETTER:
            return False

        new_job = job.model_copy(
            update={
                "state": JobState.PENDING,
                "retries": 0,
                "error": None,
                "completed_at": None,
                "worker_id": None,
                "lease_expires_at": None,
            }
        )

        new_job.compute_bid()
        job_hash = new_job.to_redis_hash()
        hash_args: list[str] = []
        for k, v in job_hash.items():
            hash_args.append(k)
            hash_args.append(v)

        await asyncio.to_thread(
            self.redis.execute_command,
            "ZREM",
            self._key(self.dead_letter_queue_name),
            self._job_key(job_id),
        )
        await asyncio.to_thread(
            self.redis.execute_script,
            "enqueue",
            keys=[self._job_key(job_id), self._key("queue")],
            args=[
                str(job.priority),
                job_id,
                str(time.time()),
                json.dumps(hash_args),
                str(new_job.bid_score),
            ],
        )

        logger.info("Re-enqueued dead-letter job %s", job_id)
        return True

    async def cancel_job(self, job_id: str) -> bool:
        job = await self.get_job(job_id)
        if job is None:
            return False

        if job.state in (JobState.COMPLETED, JobState.CANCELLED, JobState.DEAD_LETTER):
            return False

        job.mark_cancelled()

        cancel_key = self._key(f"cancelled:{job_id}")
        await asyncio.to_thread(self.redis.execute_command, "SETEX", cancel_key, 3600, "1")

        job_data = job.to_redis_hash()

        flattened_hash = []
        for k, v in job_data.items():
            flattened_hash.append(k)
            flattened_hash.append(v)

        commands = [
            ("ZREM", [self._key("queue"), self._job_key(job_id)]),
            ("HSET", [self._job_key(job_id)] + flattened_hash),
        ]
        await asyncio.to_thread(self.redis.execute_batch, commands)
        return True

    async def is_job_cancelled(self, job_id: str) -> bool:
        cancel_key = self._key(f"cancelled:{job_id}")
        result = await asyncio.to_thread(self.redis.execute_command, "EXISTS", cancel_key)
        return bool(result)

    async def get_metrics(self) -> dict[str, Any]:
        metrics_data = await asyncio.to_thread(
            self.redis.execute_command, "HGETALL", self._key("metrics")
        )
        metrics: dict[str, Any] = {}

        if metrics_data:
            for key, value in metrics_data.items():
                k = key.decode("utf-8") if isinstance(key, bytes) else key
                v = value.decode("utf-8") if isinstance(value, bytes) else value
                try:
                    metrics[k] = int(v)
                except (ValueError, TypeError):
                    metrics[k] = v

        queue_length = await self.get_queue_length()
        dlq_length = await self.get_dead_letter_count()

        metrics["queue_length"] = queue_length
        metrics["dead_letter_count"] = dlq_length
        metrics["queue_name"] = self.queue_name

        return metrics

    async def health_metrics(self, *, worker_timeout_seconds: float = 60.0) -> list[HealthMetric]:
        metrics = await self.get_metrics()
        queue_depth = int(metrics.get("queue_length", 0) or 0)
        dead_letters = int(metrics.get("dead_letter_count", 0) or 0)
        result = [
            HealthMetric(
                component=HealthComponent.QUEUE,
                name="queue_depth",
                value=queue_depth,
                labels={"queue": self.queue_name},
            ),
            HealthMetric(
                component=HealthComponent.QUEUE,
                name="dead_letter_count",
                value=dead_letters,
                status=HealthStatus.DEGRADED if dead_letters else HealthStatus.OK,
                labels={"queue": self.queue_name},
            ),
        ]

        for worker in await self._list_workers():
            heartbeat_age = max(0.0, time.time() - worker.last_heartbeat)
            result.append(
                HealthMetric(
                    component=HealthComponent.WORKER,
                    name="worker_heartbeat_age",
                    value=round(heartbeat_age, 2),
                    threshold=worker_timeout_seconds,
                    status=HealthStatus.CRITICAL
                    if heartbeat_age > worker_timeout_seconds
                    else HealthStatus.OK,
                    labels={
                        "queue": self.queue_name,
                        "worker_id": worker.id,
                        "status": worker.status,
                        "active_jobs": list(worker.active_jobs),
                    },
                )
            )
        return result

    async def heal_stale_queue_state(self, finding: Any | None = None) -> dict[str, Any]:
        worker_id = None
        if finding is not None:
            worker_id = getattr(finding, "labels", {}).get("worker_id")
        released = await self.cleanup_stale_leases(worker_id=worker_id)
        retried = 0
        for job in await self.list_dead_letters(limit=10):
            if await self.retry_dead_letter(job.id):
                retried += 1
        return {
            "queue": self.queue_name,
            "released_stale_leases": released,
            "retried_dead_letters": retried,
        }

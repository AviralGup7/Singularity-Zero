from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.models import Job, WorkerInfo

logger = get_pipeline_logger(__name__)


class JobQueueConsumerGroupsMixin:
    async def claim_job(self, worker_id: str) -> tuple[Job | None, str | None]:
        """Try to claim a job.  Returns (job, lease_version) — lease_version
        is a CAS token the caller must retain for later release/renew."""
        self._register_scripts()
        queue_key = self._key("queue")
        candidates = await asyncio.to_thread(
            self.redis.execute_command, "ZREVRANGE", queue_key, 0, 24
        )
        if not candidates:
            return (None, None)
        for candidate in candidates:
            job_key_str = candidate.decode("utf-8") if isinstance(candidate, bytes) else candidate
            job_id = job_key_str.split(":")[-1]
            result = await asyncio.to_thread(
                self.redis.execute_script,
                "claim_job",
                keys=[
                    self._job_key(job_id),
                    queue_key,
                    self._key(f"worker:{worker_id}:jobs"),
                ],
                args=[worker_id, str(self.lease_seconds), str(time.time())],
            )
            if result and int(result[0]) == 1:
                job_data = await asyncio.to_thread(
                    self.redis.execute_command, "HGETALL", self._job_key(job_id)
                )
                if job_data:
                    job = Job.from_redis_hash(job_data)
                    lease_version = str(result[2]) if len(result) >= 3 else None
                    logger.info(
                        "Worker %s claimed job %s (lease=%s)", worker_id, job_id, lease_version
                    )
                    return (job, lease_version)
        return (None, None)

    async def complete_job(
        self, job_id: str, worker_id: str, result: dict[str, Any] | None = None
    ) -> bool:
        self._register_scripts()
        result_json = json.dumps(result) if result is not None else ""
        ret = await asyncio.to_thread(
            self.redis.execute_script,
            "complete_job",
            keys=[
                self._job_key(job_id),
                self._key(f"worker:{worker_id}:jobs"),
                self._key("metrics"),
            ],
            args=[result_json, str(time.time())],
        )
        if ret and ret[0] == 1:
            logger.info("Job %s completed by worker %s", job_id, worker_id)
            return True
        logger.warning("Failed to complete job %s", job_id)
        return False

    async def fail_job(self, job_id: str, worker_id: str, error: str) -> tuple[bool, str]:
        self._register_scripts()
        job_data = await asyncio.to_thread(
            self.redis.execute_command, "HGETALL", self._job_key(job_id)
        )
        if not job_data:
            logger.warning("Job %s not found for fail operation", job_id)
            return False, "not_found"
        job = Job.from_redis_hash(job_data)
        max_retries = job.max_retries
        ret = await asyncio.to_thread(
            self.redis.execute_script,
            "fail_job",
            keys=[
                self._job_key(job_id),
                self._key(f"worker:{worker_id}:jobs"),
                self._key("queue"),
                self._key(self.dead_letter_queue_name),
                self._key("metrics"),
            ],
            args=[
                error,
                str(max_retries),
                str(time.time()),
                str(self.retry_policy.initial_delay),
                str(self.retry_policy.backoff_multiplier),
                str(self.retry_policy.max_delay),
            ],
        )
        if ret and ret[0] in (1, 2):
            outcome = "retrying" if ret[0] == 1 else "dead_letter"
            logger.info("Job %s failed, outcome=%s (max_retries=%d)", job_id, outcome, max_retries)
            return True, outcome
        logger.warning("Failed to process job failure for %s", job_id)
        return False, "error"

    async def release_lease(
        self, job_id: str, worker_id: str, lease_version: str | None = None
    ) -> bool:
        """Release a job lease.  CAS via lease_version prevents
        releasing a lease that another worker has since claimed."""
        self._register_scripts()
        ret = await asyncio.to_thread(
            self.redis.execute_script,
            "release_lease",
            keys=[
                self._job_key(job_id),
                self._key(f"worker:{worker_id}:jobs"),
                self._key("queue"),
            ],
            args=[worker_id, lease_version or ""],
        )
        if ret and int(ret[0]) == 1:
            logger.info("Released lease for job %s (worker=%s)", job_id, worker_id)
            return True
        if ret and len(ret) > 1:
            reason = str(ret[1]) if len(ret) >= 2 else "unknown"
            logger.warning(
                "Cannot release lease job=%s worker=%s: %s",
                job_id,
                worker_id,
                reason,
            )
        else:
            logger.warning("Failed to release lease for job %s", job_id)
        return False

    async def _list_workers(self) -> list[WorkerInfo]:
        workers_key = self._key("workers")
        worker_ids = await asyncio.to_thread(self.redis.execute_command, "SMEMBERS", workers_key)
        worker_ids = worker_ids or []
        workers: list[WorkerInfo] = []
        for raw_id in worker_ids:
            worker_id = raw_id.decode("utf-8") if isinstance(raw_id, bytes) else str(raw_id)
            worker_data = await asyncio.to_thread(
                self.redis.execute_command, "HGETALL", self._key(f"worker:{worker_id}")
            )
            if worker_data:
                try:
                    workers.append(WorkerInfo.from_redis_hash(worker_data))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    logger.debug("Skipping malformed worker health record %s: %s", worker_id, exc)
        return workers

    def persist_worker(self, worker: WorkerInfo) -> None:
        """Write worker health/phase so the coordinator's verdict is visible."""
        worker_key = self._key(f"worker:{worker.id}")
        self.redis.execute_command("HSET", worker_key, mapping=worker.to_redis_hash())
        workers_key = self._key("workers")
        if worker.phase == "dead" or worker.status == "dead":
            self.redis.execute_command("SREM", workers_key, worker.id)
        else:
            self.redis.execute_command("SADD", workers_key, worker.id)

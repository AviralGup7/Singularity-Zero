from __future__ import annotations

import asyncio
import time
from typing import cast

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.models import Job, JobState, WorkerInfo

logger = get_pipeline_logger(__name__)


class JobQueueRateLimiterMixin:
    async def get_next_job_for_worker(self, worker_id: str) -> Job | None:
        if not self.scheduler:
            result: Job | None = await self.claim_job(worker_id)
            return cast("Job | None", result)

        try:
            workers_key = self._key("workers")
            worker_ids = await asyncio.to_thread(
                self.redis.execute_command, "SMEMBERS", workers_key
            )
            if worker_ids:
                for w_id_bytes in worker_ids:
                    w_id = (
                        w_id_bytes.decode("utf-8")
                        if isinstance(w_id_bytes, bytes)
                        else str(w_id_bytes)
                    )
                    w_data = await asyncio.to_thread(
                        self.redis.execute_command, "HGETALL", self._key(f"worker:{w_id}")
                    )
                    if w_data:
                        try:
                            w_info = WorkerInfo.from_redis_hash(w_data)
                            self.scheduler.update_worker(w_id, w_info)
                        except Exception as exc:  # noqa: S112
                            logger.error(
                                "Failed to deserialize worker %s from Redis: %s", w_id, exc
                            )
                            try:
                                fallback_info = WorkerInfo(id=w_id, status="degraded")
                                self.scheduler.update_worker(w_id, fallback_info)
                            except (KeyError, ValueError, OSError) as fb_exc:
                                logger.debug("Worker scheduler fallback update failed: %s", fb_exc)
                            continue
        except Exception as exc:
            logger.warning("Failed to load global worker context for scheduling: %s", exc)

        queue_key = self._key("queue")
        candidates = await asyncio.to_thread(
            self.redis.execute_command, "ZREVRANGE", queue_key, 0, 49
        )
        if not candidates:
            return None

        for candidate in candidates:
            job_key_str = candidate.decode("utf-8") if isinstance(candidate, bytes) else candidate
            job_id = job_key_str.split(":")[-1]
            job_data = await asyncio.to_thread(
                self.redis.execute_command, "HGETALL", self._job_key(job_id)
            )
            if not job_data:
                continue
            job = Job.from_redis_hash(job_data)
            if job.bid_score == 0.0:
                job.compute_bid()

            best_worker = self.scheduler.select_worker(job)
            if best_worker == worker_id:
                script_result = await asyncio.to_thread(
                    self.redis.execute_script,
                    "claim_job",
                    keys=[
                        self._job_key(job_id),
                        queue_key,
                        self._key(f"worker:{worker_id}:jobs"),
                    ],
                    args=[worker_id, str(self.lease_seconds), str(time.time())],
                )
                if (
                    isinstance(script_result, list)
                    and len(script_result) > 0
                    and script_result[0] == 1
                ):
                    logger.info("Worker %s claimed job %s (scheduled)", worker_id, job_id)
                    return job
            else:
                logger.debug(
                    "Job %s (type=%s) better suited for worker %s, not %s",
                    job_id,
                    job.type,
                    best_worker,
                    worker_id,
                )
        return None

    async def cleanup_stale_leases(self, worker_id: str | None = None) -> int:
        released = 0
        if worker_id:
            worker_keys = [self._key(f"worker:{worker_id}:jobs")]
        else:
            worker_keys = []
            cursor = 0
            max_iterations = 1000
            iteration = 0
            while iteration < max_iterations:
                iteration += 1
                scan_result = await asyncio.to_thread(
                    self.redis.execute_command,
                    "SCAN",
                    cursor,
                    "MATCH",
                    self._key("worker:*:jobs"),
                    "COUNT",
                    100,
                )
                if not scan_result:
                    break
                cursor, keys = scan_result
                worker_keys.extend(keys)
                if int(cursor) == 0:
                    break
            if iteration >= max_iterations:
                logger.warning(
                    "SCAN loop hit max_iterations=%d during stale lease cleanup; partial scan only",
                    max_iterations,
                )

        for w_key in worker_keys:
            w_key_str = w_key.decode("utf-8") if isinstance(w_key, bytes) else str(w_key)
            job_ids = await asyncio.to_thread(self.redis.execute_command, "SMEMBERS", w_key_str)
            for member in job_ids or []:
                job_key_str = member.decode("utf-8") if isinstance(member, bytes) else member
                job_id = job_key_str.split(":")[-1]
                job = await self.get_job(job_id)
                if job is None:
                    continue
                if job.state not in (JobState.CLAIMED, JobState.RUNNING):
                    continue
                if job.is_lease_expired():
                    logger.warning(
                        "Releasing stale lease for job %s (worker=%s)", job_id, job.worker_id
                    )
                    await self.release_lease(job_id, job.worker_id or "unknown")
                    released += 1
        return released

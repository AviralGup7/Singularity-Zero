"""Main job queue implementation with priority scheduling and state management.

Provides the core JobQueue class with job enqueue/dequeue, priority-based
scheduling, atomic state transitions via Redis Lua scripts, lease management,
dead-letter queue handling, and configurable retry policies.
"""

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from src.core.contracts.task_envelope import TaskEnvelope
from src.core.frontier.tracing_manager import get_tracing_manager
from src.infrastructure.queue.models import Job, JobState, WorkerInfo
from src.infrastructure.queue.redis_client import RedisClient
from src.core.logging.trace_logging import get_pipeline_logger

# Fix #283: use pipeline logger instead of stdlib
logger = get_pipeline_logger(__name__)

CLAIM_JOB_SCRIPT = """
local job_key = KEYS[1]
local queue_key = KEYS[2]
local worker_key = KEYS[3]
local worker_id = ARGV[1]
local lease_seconds = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local exists = redis.call('EXISTS', job_key)
if exists == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'pending' and state ~= 'retrying' then
    return {0, 'invalid_state', state}
end

local lease_expires = now + lease_seconds
redis.call('HSET', job_key, 'state', 'claimed', 'worker_id', worker_id, 'lease_expires_at', tostring(lease_expires))
redis.call('ZREM', queue_key, job_key)
redis.call('SADD', worker_key, job_key)
return {1, 'claimed'}
"""

COMPLETE_JOB_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local metrics_key = KEYS[3]
local result_json = ARGV[1]
local now = ARGV[2]

if redis.call('EXISTS', job_key) == 0 then
    return {0}
end

redis.call('HSET', job_key, 'state', 'completed', 'completed_at', now, 'result', result_json, 'lease_expires_at', '', 'worker_id', '')
redis.call('SREM', worker_key, job_key)
redis.call('HINCRBY', metrics_key, 'completed', 1)
return {1}
"""

FAIL_JOB_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local queue_key = KEYS[3]
local dlq_key = KEYS[4]
local metrics_key = KEYS[5]
local error_msg = ARGV[1]
local retries = tonumber(ARGV[2])
local max_retries = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

redis.call('SREM', worker_key, job_key)
redis.call('HSET', job_key, 'error', error_msg)

if retries < max_retries then
    local backoff = math.floor(math.min(tonumber(ARGV[5]) * math.pow(tonumber(ARGV[6]), retries), tonumber(ARGV[7])))
    local retry_at = now + backoff
    redis.call('HSET', job_key, 'state', 'retrying', 'worker_id', '', 'lease_expires_at', '')
    redis.call('ZADD', queue_key, retry_at, job_key)
    redis.call('HINCRBY', metrics_key, 'retried', 1)
    return {1, 'retrying', tostring(retry_at)}
else
    redis.call('HSET', job_key, 'state', 'dead_letter', 'completed_at', tostring(now), 'worker_id', '', 'lease_expires_at', '')
    redis.call('ZADD', dlq_key, now, job_key)
    redis.call('HINCRBY', metrics_key, 'dead_lettered', 1)
    return {2, 'dead_letter'}
end
"""

RELEASE_LEASE_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local queue_key = KEYS[3]

if redis.call('EXISTS', job_key) == 0 then
    return {0}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'claimed' and state ~= 'running' then
    return {0}
end

redis.call('HSET', job_key, 'state', 'pending', 'worker_id', '', 'lease_expires_at', '')
redis.call('SREM', worker_key, job_key)
redis.call('ZADD', queue_key, 0, job_key)
return {1}
"""

ENQUEUE_SCRIPT = """
local job_key = KEYS[1]
local queue_key = KEYS[2]
local priority = tonumber(ARGV[1])
local job_id = ARGV[2]
local created_at = tonumber(ARGV[3])
local hash_args = cjson.decode(ARGV[4])

local score = (priority * 10000000000) - created_at
redis.call('HSET', job_key, unpack(hash_args))
redis.call('ZADD', queue_key, score, job_key)
return {1, job_id}
"""


class RetryPolicy:
    """Configurable retry policy with exponential backoff.

    Attributes:
        max_retries: Maximum number of retry attempts.
        backoff_multiplier: Multiplier for exponential backoff calculation.
        initial_delay: Initial delay in seconds before first retry.
        max_delay: Maximum delay in seconds between retries.
        jitter: Whether to add random jitter to backoff delays.
    """

    def __init__(
        self,
        max_retries: int = 3,
        backoff_multiplier: float = 2.0,
        initial_delay: float = 1.0,
        max_delay: float = 300.0,
        jitter: bool = True,
    ) -> None:
        """Initialize the retry policy.

        Args:
            max_retries: Maximum retry attempts before dead-lettering.
            backoff_multiplier: Exponential backoff multiplier.
            initial_delay: Initial delay in seconds.
            max_delay: Maximum delay cap in seconds.
            jitter: Whether to add random jitter (prevents thundering herd).
        """
        self.max_retries = max_retries
        self.backoff_multiplier = backoff_multiplier
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        """Calculate the delay before the next retry attempt.

        Uses exponential backoff with optional jitter.

        Args:
            attempt: The current retry attempt number (0-indexed).

        Returns:
            Delay in seconds before the next retry.
        """

        delay = self.initial_delay * (self.backoff_multiplier**attempt)
        delay = min(delay, self.max_delay)

        if self.jitter:
            import secrets
            # Fix #285: Use randbelow instead of instantiating SystemRandom on every call
            delay = delay * (0.5 + secrets.randbelow(1000) / 2000.0)

        return delay


class JobQueue:
    """Production-grade distributed job queue with Redis backend.

    Provides atomic job operations, priority scheduling, lease-based job
    claiming, configurable retry policies, and dead-letter queue handling.

    The queue uses Redis sorted sets for priority ordering and Lua scripts
    for atomic state transitions. An in-memory fallback is used when Redis
    is unavailable.

    Attributes:
        config: Queue configuration instance.
        redis: Redis client wrapper instance.
        retry_policy: Retry policy for failed jobs.
        _handlers: Dict mapping job types to handler functions.
        _scripts: Registered Lua script SHAs.
    """

    def __init__(
        self,
        redis_client: RedisClient,
        queue_name: str = "default",
        retry_policy: RetryPolicy | None = None,
        lease_seconds: float = 300.0,
        dead_letter_queue_name: str = "dead_letter",
        enable_scheduler: bool = True,
    ) -> None:
        """Initialize the job queue.

        Args:
            redis_client: Redis client wrapper instance.
            queue_name: Name of this queue for key namespacing.
            retry_policy: Retry policy configuration. Uses defaults if None.
            lease_seconds: Duration in seconds for job claim leases.
            dead_letter_queue_name: Name for the dead-letter queue.
            enable_scheduler: Use resource-aware scheduler.
        """
        self.redis = redis_client
        self.queue_name = queue_name
        self.retry_policy = retry_policy or RetryPolicy()
        self.lease_seconds = lease_seconds
        self.dead_letter_queue_name = dead_letter_queue_name
        self._handlers: dict[str, Callable[[Job], Any]] = {}
        self._scripts_registered = False
        self.scheduler = ResourceAwareScheduler() if enable_scheduler else None
        
        # Fix #286: Register scripts once at initialization instead of per-call
        self._register_scripts()

    def _key(self, suffix: str) -> str:
        """Generate a namespaced Redis key.

        Args:
            suffix: Key suffix (e.g., "queue", "jobs", "workers").

        Returns:
            Full namespaced key string.
        """
        return f"queue:{self.queue_name}:{suffix}"

    def _job_key(self, job_id: str) -> str:
        """Generate a Redis key for a specific job.

        Args:
            job_id: Unique job identifier.

        Returns:
            Full Redis key for the job hash.
        """
        return f"queue:{self.queue_name}:job:{job_id}"

    def _register_scripts(self) -> None:
        """Register all Lua scripts with Redis for atomic operations."""
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

        job_hash = job.to_redis_hash()
        hash_args: list[str] = []
        for k, v in job_hash.items():
            hash_args.append(k)
            hash_args.append(v)

        hash_args_json = json.dumps(hash_args)
        # Fix #284: Prevent extremely large hash_args from crashing Redis Lua engine
        if len(hash_args_json) > 1024 * 1024:
            raise ValueError(f"Task envelope too large for queue (size: {len(hash_args_json)} bytes)")

        self.redis.execute_script(
            "enqueue",
            keys=[self._job_key(job.id), self._key("queue")],
            args=[str(job.priority), job.id, str(job.created_at), hash_args_json],
        )
        logger.info(
            "Enqueued task job %s (type=%s, correlation_id=%s)",
            job.id,
            task.type,
            task.correlation_id,
        )
        return job.id

    async def claim_job(self, worker_id: str) -> Job | None:
        """Claim the highest-priority available job for a worker.

        Atomically transitions a job from PENDING/RETRYING to CLAIMED state
        and assigns it to the specified worker with a lease timeout.

        Args:
            worker_id: ID of the worker claiming the job.

        Returns:
            The claimed Job instance, or None if no jobs are available.
        """
        self._register_scripts()

        queue_key = self._key("queue")
        candidates = self.redis.execute_command("ZRANGE", queue_key, 0, 9, "REV")

        if not candidates:
            return None

        for candidate in candidates:
            job_key_str = candidate.decode("utf-8") if isinstance(candidate, bytes) else candidate
            job_id = job_key_str.split(":")[-1]

            result = self.redis.execute_script(
                "claim_job",
                keys=[
                    self._job_key(job_id),
                    queue_key,
                    self._key(f"worker:{worker_id}:jobs"),
                ],
                args=[worker_id, str(self.lease_seconds), str(time.time())],
            )

            if result and int(result[0]) == 1:
                job_data = self.redis.execute_command("HGETALL", self._job_key(job_id))
                if job_data:
                    job = Job.from_redis_hash(job_data)
                    logger.info("Worker %s claimed job %s", worker_id, job_id)
                    return job

        return None

    async def complete_job(
        self, job_id: str, worker_id: str, result: dict[str, Any] | None = None
    ) -> bool:
        """Mark a job as completed.

        Atomically transitions the job from RUNNING to COMPLETED state,
        stores the result, and removes it from the worker's active set.

        Args:
            job_id: ID of the job to complete.
            worker_id: ID of the worker completing the job.
            result: Optional result data from job execution.

        Returns:
            True if the job was successfully marked as completed.
        """
        self._register_scripts()

        result_json = json.dumps(result) if result is not None else ""

        ret = self.redis.execute_script(
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

    async def fail_job(
        self,
        job_id: str,
        worker_id: str,
        error: str,
    ) -> tuple[bool, str]:
        """Mark a job as failed, with automatic retry or dead-letter handling.

        Atomically handles the failure by either:
        - Scheduling a retry with exponential backoff if retries remain
        - Moving to the dead-letter queue if max retries exhausted

        Args:
            job_id: ID of the failed job.
            worker_id: ID of the worker that was processing the job.
            error: Error message describing the failure.

        Returns:
            Tuple of (success, outcome) where outcome is 'retrying' or 'dead_letter'.
        """
        self._register_scripts()

        job_data = self.redis.execute_command("HGETALL", self._job_key(job_id))
        if not job_data:
            logger.warning("Job %s not found for fail operation", job_id)
            return False, "not_found"

        job = Job.from_redis_hash(job_data)
        retries = job.retries
        max_retries = job.max_retries
        # Fix #287: removed dead self.retry_policy.get_delay(retries) call

        ret = self.redis.execute_script(
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
                str(retries),
                str(max_retries),
                str(time.time()),
                str(self.retry_policy.initial_delay),
                str(self.retry_policy.backoff_multiplier),
                str(self.retry_policy.max_delay),
            ],
        )

        if ret and ret[0] in (1, 2):
            outcome = "retrying" if ret[0] == 1 else "dead_letter"
            logger.info(
                "Job %s failed, outcome=%s (retries=%d/%d)", job_id, outcome, retries, max_retries
            )
            return True, outcome

        logger.warning("Failed to process job failure for %s", job_id)
        return False, "error"

    async def release_lease(self, job_id: str, worker_id: str) -> bool:
        """Release a job's lease, returning it to the pending queue.

        Used when a worker needs to gracefully release a job without
        completing or failing it (e.g., during shutdown).

        Args:
            job_id: ID of the job to release.
            worker_id: ID of the worker releasing the lease.

        Returns:
            True if the lease was successfully released.
        """
        self._register_scripts()

        ret = self.redis.execute_script(
            "release_lease",
            keys=[
                self._job_key(job_id),
                self._key(f"worker:{worker_id}:jobs"),
                self._key("queue"),
            ],
            args=[],
        )

        if ret and ret[0] == 1:
            logger.info("Released lease for job %s", job_id)
            return True

        logger.warning("Failed to release lease for job %s", job_id)
        return False

    async def get_job(self, job_id: str) -> Job | None:
        """Retrieve a job by its ID.

        Args:
            job_id: Unique job identifier.

        Returns:
            Job instance if found, None otherwise.
        """
        job_data = self.redis.execute_command("HGETALL", self._job_key(job_id))
        if not job_data:
            return None
        return Job.from_redis_hash(job_data)

    async def get_queue_length(self) -> int:
        """Get the number of jobs waiting in the queue.

        Returns:
            Number of pending/retrying jobs in the queue.
        """
        result = self.redis.execute_command("ZCARD", self._key("queue"))
        return int(result) if result else 0

    async def get_dead_letter_count(self) -> int:
        """Get the number of jobs in the dead-letter queue.

        Returns:
            Number of dead-lettered jobs.
        """
        result = self.redis.execute_command("ZCARD", self._key(self.dead_letter_queue_name))
        return int(result) if result else 0

    async def list_dead_letters(self, limit: int = 50) -> list[Job]:
        """List jobs in the dead-letter queue.

        Args:
            limit: Maximum number of jobs to return.

        Returns:
            List of Job instances from the dead-letter queue.
        """
        members = self.redis.execute_command(
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

        for member in members:
            job_key_str = member.decode("utf-8") if isinstance(member, bytes) else member
            job_id = job_key_str.split(":")[-1]
            job = await self.get_job(job_id)
            if job is not None:
                jobs.append(job)

        return jobs

    async def retry_dead_letter(self, job_id: str) -> bool:
        """Re-enqueue a dead-lettered job for reprocessing.

        Resets the job state to PENDING and adds it back to the main queue.

        Args:
            job_id: ID of the dead-letter job to retry.

        Returns:
            True if the job was successfully re-enqueued.
        """
        job = await self.get_job(job_id)
        if job is None or job.state != JobState.DEAD_LETTER:
            return False

        # Fix #288: Mutating a Pydantic model directly can fail if it's frozen or tracked.
        # Create a new copy instead.
        new_job = job.model_copy(update={
            "state": JobState.PENDING,
            "retries": 0,
            "error": None,
            "completed_at": None,
            "worker_id": None,
            "lease_expires_at": None,
        })

        job_hash = new_job.to_redis_hash()
        hash_args: list[str] = []
        for k, v in job_hash.items():
            hash_args.append(k)
            hash_args.append(v)

        self.redis.execute_command(
            "ZREM", self._key(self.dead_letter_queue_name), self._job_key(job_id)
        )
        self.redis.execute_script(
            "enqueue",
            keys=[self._job_key(job_id), self._key("queue")],
            args=[str(job.priority), job_id, str(time.time()), json.dumps(hash_args)],
        )

        logger.info("Re-enqueued dead-letter job %s", job_id)
        return True

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job.

        Transitions the job to CANCELLED state and removes it from
        the active queue.

        Args:
            job_id: ID of the job to cancel.

        Returns:
            True if the job was successfully cancelled.
        """
        job = await self.get_job(job_id)
        if job is None:
            return False

        if job.state in (JobState.COMPLETED, JobState.CANCELLED, JobState.DEAD_LETTER):
            return False

        job.mark_cancelled()

        job_data = job.to_redis_hash()
        pipe = self.redis.client
        # Fix #289: Access using getattr to avoid breaking encapsulation directly
        is_fallback = getattr(self.redis, "is_fallback", getattr(self.redis, "_use_fallback", False))
        if pipe is not None and not is_fallback:
            try:
                pipeline = pipe.pipeline()
                pipeline.zrem(self._key("queue"), self._job_key(job_id))
                pipeline.hset(self._job_key(job_id), mapping=job_data)
                pipeline.execute()
                return True
            except Exception as exc:
                # Fix #290: Log pipeline execution failure instead of silent pass
                logger.warning("Pipeline execution failed while cancelling job %s: %s", job_id, exc)

        self.redis.execute_command("HSET", self._job_key(job_id), mapping=job_data)
        return True

    async def get_metrics(self) -> dict[str, Any]:
        """Retrieve queue metrics.

        Returns:
            Dict with queue statistics including lengths, rates, and state counts.
        """
        metrics_data = self.redis.execute_command("HGETALL", self._key("metrics"))
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

    async def get_next_job_for_worker(self, worker_id: str) -> Job | None:
        """Get the next job that is suitable for this worker.

        Uses the resource-aware scheduler to check if the worker
        is the best fit for the highest-priority job.

        Args:
            worker_id: ID of the worker requesting a job.

        Returns:
            Job if a suitable job is available, None otherwise.
        """
        if not self.scheduler:
            # Scheduler disabled, use default behavior
            return await self.claim_job(worker_id)

        # Load all active workers into scheduler for global context
        try:
            workers_key = self._key("workers")
            worker_ids = self.redis.execute_command("SMEMBERS", workers_key)
            if worker_ids:
                for w_id_bytes in worker_ids:
                    w_id = w_id_bytes.decode("utf-8") if isinstance(w_id_bytes, bytes) else str(w_id_bytes)
                    w_data = self.redis.execute_command("HGETALL", self._key(f"worker:{w_id}"))
                    if w_data:
                        try:
                            w_info = WorkerInfo.from_redis_hash(w_data)
                            self.scheduler.update_worker(w_id, w_info)
                        except Exception:
                            continue
        except Exception as exc:
            logger.warning("Failed to load global worker context for scheduling: %s", exc)

        # Get candidates from the queue
        queue_key = self._key("queue")
        candidates = self.redis.execute_command("ZRANGE", queue_key, 0, 9, "REV")

        if not candidates:
            return None

        for candidate in candidates:
            job_key_str = candidate.decode("utf-8") if isinstance(candidate, bytes) else candidate
            job_id = job_key_str.split(":")[-1]
            job_data = self.redis.execute_command("HGETALL", self._job_key(job_id))
            if not job_data:
                continue

            job = Job.from_redis_hash(job_data)

            # Check if this worker is the best fit
            best_worker = self.scheduler.select_worker(job)
            if best_worker == worker_id:
                # This worker is the best fit, claim it
                result = self.redis.execute_script(
                    "claim_job",
                    keys=[
                        self._job_key(job_id),
                        queue_key,
                        self._key(f"worker:{worker_id}:jobs"),
                    ],
                    args=[worker_id, str(self.lease_seconds), str(time.time())],
                )
                if result and result[0] == 1:
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

    def register_handler(self, job_type: str, handler: Callable[[Job], Any]) -> None:
        """Register a handler function for a specific job type.

        Args:
            job_type: Job type string to match.
            handler: Callable that accepts a Job and returns execution result.
        """
        self._handlers[job_type] = handler
        logger.info("Registered handler for job type: %s", job_type)

    def get_handler(self, job_type: str) -> Callable[[Job], Any] | None:
        """Get the registered handler for a job type.

        Args:
            job_type: Job type string to look up.

        Returns:
            Handler function if registered, None otherwise.
        """
        return self._handlers.get(job_type)

    async def cleanup_stale_leases(self, worker_id: str | None = None) -> int:
        """Find and release jobs with expired leases.

        Scans the queue for claimed/running jobs whose lease has expired
        and returns them to the pending state.

        Args:
            worker_id: If provided, only check jobs for this worker.

        Returns:
            Number of stale leases released.
        """
        released = 0
        # Fix #291: ZRANGEBYSCORE over the entire queue is O(n) and blocks Redis.
        # Also, claimed jobs are in worker tracking sets, not the main queue.
        # We iterate over worker job sets using SCAN/SMEMBERS instead.
        if worker_id:
            worker_keys = [self._key(f"worker:{worker_id}:jobs")]
        else:
            worker_keys = []
            cursor = 0
            while True:
                # Use SCAN to find all worker job sets without blocking
                cursor, keys = self.redis.execute_command("SCAN", cursor, "MATCH", self._key("worker:*:jobs"), "COUNT", 100)
                worker_keys.extend(keys)
                if int(cursor) == 0:
                    break

        for w_key in worker_keys:
            job_ids = self.redis.execute_command("SMEMBERS", w_key)
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

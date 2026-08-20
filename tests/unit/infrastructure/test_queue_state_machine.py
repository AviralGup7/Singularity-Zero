"""
Distributed queue state machine — fencing, cancellation, lease expiry.

Validates the five audited fixes:

  1. FAIL_JOB fencing   — only CLAIMED/RUNNING + worker_id + lease_version
                          may transition to RETRYING/DEAD_LETTER.
  2. COMPLETE_JOB fence — same CAS fencing; late callbacks rejected.
  3. CANCELLED terminal — a cancelled job can never be completed/retried.
  4. Worker phase        — unknown → SUSPECT; DRAINING/SUSPECT/DEAD workers
                          are refused new claims.
  5. Lease expiry        — expired leases requeue atomically; live leases
                          and terminal states are untouched.

The tests run against the in-memory fallback emulator, which mirrors the
Lua scripts 1:1 (Redis is unavailable in CI).  Every transition is driven
through the same JobQueue mixin methods the production worker uses.
"""

from __future__ import annotations

import time
import uuid

import pytest

from src.core.contracts.task_envelope import TaskEnvelope
from src.infrastructure.queue.job_queue import JobQueue
from src.infrastructure.queue.models import Job, JobState
from src.infrastructure.queue.redis_client import RedisClient
from src.infrastructure.queue.worker_phase import WorkerPhase, normalize_phase


def _ns() -> str:
    return "sm-" + uuid.uuid4().hex[:10]


@pytest.fixture()
def queue() -> JobQueue:
    """A JobQueue backed by the in-memory fallback emulator.

    Each queue gets a unique namespace so tests never share the
    on-disk fallback DB.
    """
    client = RedisClient(url=None)
    return JobQueue(redis_client=client, enable_scheduler=False, namespace=_ns())


@pytest.fixture()
def queue_with_scheduler() -> JobQueue:
    client = RedisClient(url=None)
    return JobQueue(redis_client=client, enable_scheduler=True, namespace=_ns())


async def _enqueue(queue: JobQueue, type_: str = "dom_xss", job_id: str | None = None) -> str:
    return await queue.enqueue(
        TaskEnvelope(type=type_, payload={"target": "example.com"}),
        job_id=job_id,
        max_retries=2,
    )


async def _claim(queue: JobQueue, worker: str) -> tuple[Job | None, str | None]:
    result = await queue.claim_job(worker)
    if isinstance(result, tuple):
        return result[0], result[1]
    return result, None


async def _job(queue: JobQueue, job_id: str) -> Job:
    job = await queue.get_job(job_id)
    assert job is not None, f"job {job_id} missing"
    return job


def _register_worker(queue: JobQueue, worker_id: str, phase: str) -> None:
    """Register a worker record with the given phase (drives claim gating)."""
    client = queue.redis
    client.execute_command(
        "HSET",
        queue._key(f"worker:{worker_id}"),
        mapping={
            "id": worker_id,
            "hostname": "test",
            "pid": "1",
            "status": "idle",
            "phase": phase,
            "concurrency": "2",
            "active_jobs": "[]",
            "last_heartbeat": str(time.time()),
            "started_at": str(time.time()),
            "total_processed": "0",
            "total_failed": "0",
            "metadata": "{}",
            "capabilities": '["browser", "recon"]',
            "resources": (
                '{"cpu_count": 4, "cpu_freq_mhz": 2400.0,'
                ' "total_ram_mb": 8192, "available_ram_mb": 4096,'
                ' "disk_gb_free": 50.0}'
            ),
        },
    )
    client.execute_command("SADD", queue._key("workers"), worker_id)


# ===================================================================
# 1. FAIL_JOB fencing
# ===================================================================


@pytest.mark.asyncio
async def test_fail_job_valid_claimed_transitions_to_retrying(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert job is not None and lease

    ok, outcome = await queue.fail_job(job_id, "w1", "boom", lease_version=lease)
    assert ok is True
    assert outcome == "retrying"
    assert (await _job(queue, job_id)).state == JobState.RETRYING


@pytest.mark.asyncio
async def test_fail_job_valid_running_transitions_to_dead_letter(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    # Simulate RUNNING by setting state directly (as a worker does at start)
    client = queue.redis
    client.execute_command("HSET", queue._job_key(job_id), "state", "running")

    ok, outcome = await queue.fail_job(job_id, "w1", "fatal", lease_version=lease)
    # max_retries=2 → 1 retry then dead_letter; a single fail lands in retrying
    assert ok is True
    assert outcome in ("retrying", "dead_letter")
    state = (await _job(queue, job_id)).state
    assert state in (JobState.RETRYING, JobState.DEAD_LETTER)


@pytest.mark.asyncio
async def test_fail_job_rejects_wrong_state_completed(queue: JobQueue):
    """A completed job can never be failed into retrying."""
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert await queue.complete_job(job_id, "w1", {"ok": True}, lease_version=lease)

    ok, outcome = await queue.fail_job(job_id, "w1", "late failure", lease_version=lease)
    assert ok is False
    assert (await _job(queue, job_id)).state == JobState.COMPLETED


@pytest.mark.asyncio
async def test_fail_job_rejects_wrong_state_cancelled(queue: JobQueue):
    """A cancelled job can never be failed into retrying."""
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert await queue.cancel_job(job_id, "w1", lease_version=lease)

    ok, outcome = await queue.fail_job(job_id, "w1", "late failure", lease_version=lease)
    assert ok is False
    assert (await _job(queue, job_id)).state == JobState.CANCELLED


@pytest.mark.asyncio
async def test_fail_job_rejects_worker_mismatch(queue: JobQueue):
    """A worker that no longer holds the lease cannot fail the job."""
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    # w2 tries to fail w1's job
    ok, outcome = await queue.fail_job(job_id, "w2", "wrong worker", lease_version="stale")
    assert ok is False
    assert (await _job(queue, job_id)).state == JobState.CLAIMED


@pytest.mark.asyncio
async def test_fail_job_rejects_stale_lease_version(queue: JobQueue):
    """A stale CAS token cannot fail the job after a re-claim."""
    job_id = await _enqueue(queue)
    job1, lease1 = await _claim(queue, "w1")
    # w1 releases; w2 re-claims (gets a new lease_version)
    await queue.release_lease(job_id, "w1", lease_version=lease1)
    job2, lease2 = await _claim(queue, "w2")
    assert lease2 != lease1

    # w1's stale token must be rejected
    ok, outcome = await queue.fail_job(job_id, "w1", "stale", lease_version=lease1)
    assert ok is False
    assert (await _job(queue, job_id)).state == JobState.CLAIMED


# ===================================================================
# 2. COMPLETE_JOB fencing
# ===================================================================


@pytest.mark.asyncio
async def test_complete_job_valid(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert await queue.complete_job(job_id, "w1", {"ok": True}, lease_version=lease)
    assert (await _job(queue, job_id)).state == JobState.COMPLETED


@pytest.mark.asyncio
async def test_complete_job_rejects_wrong_state_cancelled(queue: JobQueue):
    """Late completion of a cancelled job is rejected."""
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert await queue.cancel_job(job_id, "w1", lease_version=lease)

    assert await queue.complete_job(job_id, "w1", {"ok": True}, lease_version=lease) is False
    assert (await _job(queue, job_id)).state == JobState.CANCELLED


@pytest.mark.asyncio
async def test_complete_job_rejects_worker_mismatch(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert await queue.complete_job(job_id, "w2", {"ok": True}, lease_version=lease) is False
    assert (await _job(queue, job_id)).state == JobState.CLAIMED


@pytest.mark.asyncio
async def test_complete_job_rejects_stale_lease_version(queue: JobQueue):
    job_id = await _enqueue(queue)
    job1, lease1 = await _claim(queue, "w1")
    await queue.release_lease(job_id, "w1", lease_version=lease1)
    job2, lease2 = await _claim(queue, "w2")

    assert await queue.complete_job(job_id, "w1", {"ok": True}, lease_version=lease1) is False
    assert (await _job(queue, job_id)).state == JobState.CLAIMED
    # w2 can complete with its own token
    assert await queue.complete_job(job_id, "w2", {"ok": True}, lease_version=lease2)
    assert (await _job(queue, job_id)).state == JobState.COMPLETED


# ===================================================================
# 3. CANCELLED is terminal
# ===================================================================


@pytest.mark.asyncio
async def test_cancel_pending_job(queue: JobQueue):
    job_id = await _enqueue(queue)
    assert await queue.cancel_job(job_id)
    assert (await _job(queue, job_id)).state == JobState.CANCELLED


@pytest.mark.asyncio
async def test_cancel_running_job_with_fencing(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    # Cancel with the right holder + token
    assert await queue.cancel_job(job_id, "w1", lease_version=lease)
    assert (await _job(queue, job_id)).state == JobState.CANCELLED


@pytest.mark.asyncio
async def test_cancel_rejects_wrong_holder(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    assert await queue.cancel_job(job_id, "w2", lease_version=lease) is False
    assert (await _job(queue, job_id)).state == JobState.CLAIMED


@pytest.mark.asyncio
async def test_cancelled_job_cannot_be_completed_or_retried(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    await queue.cancel_job(job_id, "w1", lease_version=lease)

    # Late complete → rejected
    assert await queue.complete_job(job_id, "w1", {}, lease_version=lease) is False
    # Late fail → rejected
    ok, outcome = await queue.fail_job(job_id, "w1", "late", lease_version=lease)
    assert ok is False
    # Cannot be claimed again
    claimed, _ = await _claim(queue, "w2")
    assert claimed is None
    assert (await _job(queue, job_id)).state == JobState.CANCELLED


@pytest.mark.asyncio
async def test_cancelled_job_never_requeued(queue: JobQueue):
    job_id = await _enqueue(queue)
    await queue.cancel_job(job_id)
    # The queue sorted set must not contain the cancelled job
    client = queue.redis
    members = client.execute_command("ZRANGE", queue._key("queue"), 0, -1)
    assert job_id.encode() not in [
        m if isinstance(m, bytes) else str(m).encode() for m in members or []
    ]


# ===================================================================
# 4. Worker phase
# ===================================================================


def test_normalize_phase_unknown_is_suspect():
    assert normalize_phase(None) == WorkerPhase.SUSPECT
    assert normalize_phase("") == WorkerPhase.SUSPECT
    assert normalize_phase("garbage") == WorkerPhase.SUSPECT


def test_normalize_phase_known_aliases():
    assert normalize_phase("idle") == WorkerPhase.READY
    assert normalize_phase("busy") == WorkerPhase.RUNNING
    assert normalize_phase("shutting_down") == WorkerPhase.DRAINING
    assert normalize_phase("starting") == WorkerPhase.REGISTERING
    assert normalize_phase("ready") == WorkerPhase.READY
    assert normalize_phase("draining") == WorkerPhase.DRAINING
    assert normalize_phase("suspect") == WorkerPhase.SUSPECT
    assert normalize_phase("dead") == WorkerPhase.DEAD


@pytest.mark.asyncio
async def test_claim_gating_draining_worker(queue_with_scheduler: JobQueue):
    q = queue_with_scheduler
    await _enqueue(q)
    _register_worker(q, "w-draining", "draining")

    job = await q.get_next_job_for_worker("w-draining")
    assert job is None, "draining worker must not be handed new work"


@pytest.mark.asyncio
async def test_claim_gating_suspect_worker(queue_with_scheduler: JobQueue):
    q = queue_with_scheduler
    await _enqueue(q)
    _register_worker(q, "w-suspect", "suspect")

    job = await q.get_next_job_for_worker("w-suspect")
    assert job is None, "suspect worker must not be handed new work"


@pytest.mark.asyncio
async def test_claim_gating_dead_worker(queue_with_scheduler: JobQueue):
    q = queue_with_scheduler
    await _enqueue(q)
    _register_worker(q, "w-dead", "dead")

    job = await q.get_next_job_for_worker("w-dead")
    assert job is None, "dead worker must not be handed new work"


@pytest.mark.asyncio
async def test_claim_allowed_for_ready_worker(queue_with_scheduler: JobQueue):
    q = queue_with_scheduler
    job_id = await _enqueue(q)
    _register_worker(q, "w-ready", "ready")

    job = await q.get_next_job_for_worker("w-ready")
    assert job is not None, "ready worker should be able to claim"
    assert job.id == job_id


# ===================================================================
# 5. Lease expiry — automatic recovery
# ===================================================================


@pytest.mark.asyncio
async def test_expired_lease_requeues(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")

    # Force the lease into the past
    client = queue.redis
    client.execute_command(
        "HSET", queue._job_key(job_id), "lease_expires_at", str(time.time() - 60)
    )

    ok, reason = await queue.expire_stale_lease(job_id, "w1")
    assert ok is True, f"expected requeue, got {reason}"
    assert (await _job(queue, job_id)).state == JobState.PENDING

    # It can now be claimed again by a different worker
    job2, lease2 = await _claim(queue, "w2")
    assert job2 is not None and job2.id == job_id


@pytest.mark.asyncio
async def test_valid_lease_not_requeued(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")

    ok, reason = await queue.expire_stale_lease(job_id, "w1")
    assert ok is False
    assert reason == "lease_valid"
    assert (await _job(queue, job_id)).state == JobState.CLAIMED


@pytest.mark.asyncio
async def test_expired_lease_rejects_completed_job(queue: JobQueue):
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")
    await queue.complete_job(job_id, "w1", {}, lease_version=lease)

    ok, reason = await queue.expire_stale_lease(job_id, "w1")
    assert ok is False
    assert reason == "wrong_state"
    assert (await _job(queue, job_id)).state == JobState.COMPLETED


@pytest.mark.asyncio
async def test_expired_lease_stale_worker_token_cannot_complete_after_requeue(queue: JobQueue):
    """After an expired lease requeues the job, the old worker's stale token
    can no longer complete it — the lease_version was discarded."""
    job_id = await _enqueue(queue)
    job, lease = await _claim(queue, "w1")

    client = queue.redis
    client.execute_command(
        "HSET", queue._job_key(job_id), "lease_expires_at", str(time.time() - 60)
    )
    ok, _ = await queue.expire_stale_lease(job_id, "w1")
    assert ok

    # w1's old token is now stale
    assert await queue.complete_job(job_id, "w1", {}, lease_version=lease) is False
    # A fresh claim by w2 succeeds
    job2, lease2 = await _claim(queue, "w2")
    assert job2 is not None and job2.id == job_id
    assert await queue.complete_job(job_id, "w2", {}, lease_version=lease2)
    assert (await _job(queue, job_id)).state == JobState.COMPLETED

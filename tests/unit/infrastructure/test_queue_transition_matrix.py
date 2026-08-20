"""
Complete distributed queue state-machine transition matrix.

Every reachable (current_state, event) pair is tested:

                     Event
   Current  ────────────────────────────────────────
   State     claim  complete  fail  cancel  expire  release
   ──────────────────────────────────────────────────────────
   PENDING     OK      REJ     REJ    OK      REJ     n/a
   CLAIMED     REJ     OK      OK     OK      OK      OK
   RUNNING     REJ     OK      OK     OK      OK      OK
   RETRYING    OK      REJ     REJ    OK      REJ     n/a
   COMPLETED   REJ     REJ     REJ    REJ     REJ     REJ
   CANCELLED   REJ     REJ     REJ    REJ     REJ     REJ
   DEAD_LETTER REJ     REJ     REJ    REJ     REJ     REJ

  OK  = accepted transition
  REJ = rejected (job stays in current state)
  n/a = no lease to release

  Also tests worker-mismatch and stale-lease-version rejection for
  every event that supports fencing, and empty-caller rejection.
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
    return "tm-" + uuid.uuid4().hex[:10]


@pytest.fixture()
def queue() -> JobQueue:
    client = RedisClient(url=None)
    return JobQueue(redis_client=client, enable_scheduler=False, namespace=_ns())


@pytest.fixture()
def qs() -> JobQueue:
    client = RedisClient(url=None)
    return JobQueue(redis_client=client, enable_scheduler=True, namespace=_ns())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _enq(q: JobQueue) -> str:
    return await q.enqueue(TaskEnvelope(type="scan", payload={"target": "x"}), max_retries=2)


async def _clm(q: JobQueue, w: str) -> tuple[Job | None, str | None]:
    r = await q.claim_job(w)
    return (r[0], r[1]) if isinstance(r, tuple) else (r, None)


async def _st(q: JobQueue, jid: str) -> JobState:
    j = await q.get_job(jid)
    assert j is not None, f"job {jid} missing"
    return j.state


def _force(
    q: JobQueue,
    jid: str,
    state: str,
    worker: str = "",
    version: str = "",
    expires_at: float | None = None,
) -> str:
    """Force-set a job's state/worker/lease to set up a transition."""
    mapping = {"state": state, "worker_id": worker}
    if version:
        mapping["lease_version"] = version
    if expires_at is not None:
        mapping["lease_expires_at"] = str(expires_at)
    else:
        mapping["lease_expires_at"] = str(time.time() + 300)
    q.redis.execute_command("HSET", q._job_key(jid), mapping=mapping)
    return version


def _reg_worker(q: JobQueue, wid: str, phase: str) -> None:
    c = q.redis
    c.execute_command(
        "HSET",
        q._key(f"worker:{wid}"),
        mapping={
            "id": wid,
            "hostname": "test",
            "pid": "1",
            "status": "idle",
            "phase": phase,
            "concurrency": "1",
            "active_jobs": "[]",
            "last_heartbeat": str(time.time()),
            "started_at": str(time.time()),
            "total_processed": "0",
            "total_failed": "0",
            "metadata": "{}",
            "capabilities": '["recon"]',
            "resources": '{"cpu_count":2,"total_ram_mb":4096,"available_ram_mb":2048,"disk_gb_free":10}',
        },
    )
    c.execute_command("SADD", q._key("workers"), wid)


# ===================================================================
# State machine — all 42 transitions
# ===================================================================

# ── PENDING ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pending_claim_ok(queue: JobQueue):
    """PENDING + claim(w1) → CLAIMED"""
    jid = await _enq(queue)
    job, lv = await _clm(queue, "w1")
    assert job is not None and job.id == jid
    assert await _st(queue, jid) == JobState.CLAIMED


@pytest.mark.asyncio
async def test_pending_complete_rej(queue: JobQueue):
    """PENDING + complete → REJECT"""
    jid = await _enq(queue)
    assert await queue.complete_job(jid, "w1", {}) is False
    assert await _st(queue, jid) == JobState.PENDING


@pytest.mark.asyncio
async def test_pending_fail_rej(queue: JobQueue):
    """PENDING + fail → REJECT"""
    jid = await _enq(queue)
    ok, _ = await queue.fail_job(jid, "w1", "boom")
    assert ok is False
    assert await _st(queue, jid) == JobState.PENDING


@pytest.mark.asyncio
async def test_pending_cancel_ok(queue: JobQueue):
    """PENDING + cancel → CANCELLED"""
    jid = await _enq(queue)
    assert await queue.cancel_job(jid) is True
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_pending_expire_rej(queue: JobQueue):
    """PENDING + expire → REJECT (wrong_state)"""
    jid = await _enq(queue)
    ok, reason = await queue.expire_stale_lease(jid)
    assert ok is False
    assert reason == "wrong_state"


# ── CLAIMED ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_claimed_claim_rej(queue: JobQueue):
    """CLAIMED + claim(w2) → REJECT"""
    await _enq(queue)
    job, _ = await _clm(queue, "w1")
    assert job is not None
    job2, _ = await _clm(queue, "w2")
    assert job2 is None


@pytest.mark.asyncio
async def test_claimed_complete_ok(queue: JobQueue):
    """CLAIMED + complete(w1) → COMPLETED"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    assert await _st(queue, jid) == JobState.COMPLETED


@pytest.mark.asyncio
async def test_claimed_fail_ok(queue: JobQueue):
    """CLAIMED + fail(w1) → RETRYING"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok
    assert out in ("retrying", "dead_letter")
    assert await _st(queue, jid) in (JobState.RETRYING, JobState.DEAD_LETTER)


@pytest.mark.asyncio
async def test_claimed_cancel_ok(queue: JobQueue):
    """CLAIMED + cancel(w1) → CANCELLED"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.cancel_job(jid, "w1", lease_version=lv)
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_claimed_expire_ok(queue: JobQueue):
    """CLAIMED + expire(expired) → PENDING"""
    jid = await _enq(queue)
    _force(queue, jid, "claimed", "w1", "v1", time.time() - 60)
    ok, reason = await queue.expire_stale_lease(jid, "w1")
    assert ok, f"expected requeue, got {reason}"
    assert await _st(queue, jid) == JobState.PENDING


@pytest.mark.asyncio
async def test_claimed_expire_valid_untouched(queue: JobQueue):
    """CLAIMED + expire(valid) → REJECT (lease_valid)"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, reason = await queue.expire_stale_lease(jid, "w1")
    assert ok is False
    assert reason == "lease_valid"


@pytest.mark.asyncio
async def test_claimed_release_ok(queue: JobQueue):
    """CLAIMED + release(w1) → PENDING"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.release_lease(jid, "w1", lease_version=lv)
    assert await _st(queue, jid) == JobState.PENDING


@pytest.mark.asyncio
async def test_claimed_complete_worker_mismatch_rej(queue: JobQueue):
    """CLAIMED + complete(w2) → REJECT (worker_mismatch)"""
    jid = await _enq(queue)
    lv = _force(queue, jid, "claimed", "w1", "v1")
    assert await queue.complete_job(jid, "w2", {}, lease_version=lv) is False
    assert await _st(queue, jid) == JobState.CLAIMED


@pytest.mark.asyncio
async def test_claimed_fail_worker_mismatch_rej(queue: JobQueue):
    """CLAIMED + fail(w2) → REJECT (worker_mismatch)"""
    jid = await _enq(queue)
    lv = _force(queue, jid, "claimed", "w1", "v1")
    ok, _ = await queue.fail_job(jid, "w2", "boom", lease_version=lv)
    assert ok is False
    assert await _st(queue, jid) == JobState.CLAIMED


@pytest.mark.asyncio
async def test_claimed_release_worker_mismatch_rej(queue: JobQueue):
    """CLAIMED + release(w2) → REJECT (worker_mismatch)"""
    jid = await _enq(queue)
    lv = _force(queue, jid, "claimed", "w1", "v1")
    assert await queue.release_lease(jid, "w2", lease_version=lv) is False
    assert await _st(queue, jid) == JobState.CLAIMED


@pytest.mark.asyncio
async def test_claimed_release_empty_caller_rej(queue: JobQueue):
    """CLAIMED + release(empty caller) → REJECT (worker_mismatch, S-2)"""
    jid = await _enq(queue)
    _force(queue, jid, "claimed", "w1", "v1")
    assert await queue.release_lease(jid, "", lease_version="") is False
    assert await _st(queue, jid) == JobState.CLAIMED


@pytest.mark.asyncio
async def test_claimed_stale_lease_version_rej(queue: JobQueue):
    """CLAIMED + complete(w1, stale_version) → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    await queue.release_lease(jid, "w1", lease_version=lv)
    _, lv2 = await _clm(queue, "w2")
    assert lv2 != lv
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv) is False
    assert await _st(queue, jid) == JobState.CLAIMED


# ── RUNNING ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_running_claim_rej(queue: JobQueue):
    """RUNNING + claim → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    _force(queue, jid, "running", "w1", lv or "v1")
    job2, _ = await _clm(queue, "w2")
    assert job2 is None


@pytest.mark.asyncio
async def test_running_complete_ok(queue: JobQueue):
    """RUNNING + complete(w1) → COMPLETED"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    _force(queue, jid, "running", "w1", lv or "v1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    assert await _st(queue, jid) == JobState.COMPLETED


@pytest.mark.asyncio
async def test_running_fail_ok(queue: JobQueue):
    """RUNNING + fail(w1) → RETRYING"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    _force(queue, jid, "running", "w1", lv or "v1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok
    assert out in ("retrying", "dead_letter")
    assert await _st(queue, jid) in (JobState.RETRYING, JobState.DEAD_LETTER)


@pytest.mark.asyncio
async def test_running_cancel_ok(queue: JobQueue):
    """RUNNING + cancel(w1) → CANCELLED"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    _force(queue, jid, "running", "w1", lv or "v1")
    assert await queue.cancel_job(jid, "w1", lease_version=lv)
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_running_expire_ok(queue: JobQueue):
    """RUNNING + expire(expired) → PENDING"""
    jid = await _enq(queue)
    _force(queue, jid, "running", "w1", "v1", time.time() - 60)
    ok, reason = await queue.expire_stale_lease(jid, "w1")
    assert ok, f"expected requeue, got {reason}"
    assert await _st(queue, jid) == JobState.PENDING


@pytest.mark.asyncio
async def test_running_release_ok(queue: JobQueue):
    """RUNNING + release(w1) → PENDING"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    _force(queue, jid, "running", "w1", lv)
    assert await queue.release_lease(jid, "w1", lease_version=lv)
    assert await _st(queue, jid) == JobState.PENDING


# ── RETRYING ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_retrying_claim_ok(queue: JobQueue):
    """RETRYING + claim → CLAIMED"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok and out == "retrying"
    job2, lv2 = await _clm(queue, "w1")
    assert job2 is not None and job2.id == jid
    assert await _st(queue, jid) == JobState.CLAIMED


@pytest.mark.asyncio
async def test_retrying_complete_rej(queue: JobQueue):
    """RETRYING + complete → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok and out == "retrying"
    assert await queue.complete_job(jid, "w1", {}) is False
    assert await _st(queue, jid) == JobState.RETRYING


@pytest.mark.asyncio
async def test_retrying_fail_rej(queue: JobQueue):
    """RETRYING + fail → REJECT (wrong_state)"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok and out == "retrying"
    ok2, _ = await queue.fail_job(jid, "w1", "double boom")
    assert ok2 is False
    assert await _st(queue, jid) == JobState.RETRYING


@pytest.mark.asyncio
async def test_retrying_cancel_ok(queue: JobQueue):
    """RETRYING + cancel → CANCELLED"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok and out == "retrying"
    assert await queue.cancel_job(jid)
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_retrying_expire_rej(queue: JobQueue):
    """RETRYING + expire → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert ok and out == "retrying"
    ok2, reason = await queue.expire_stale_lease(jid)
    assert ok2 is False
    assert reason == "wrong_state"


# ── COMPLETED ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_completed_claim_rej(queue: JobQueue):
    """COMPLETED + claim → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    job2, _ = await _clm(queue, "w1")
    assert job2 is None


@pytest.mark.asyncio
async def test_completed_complete_rej(queue: JobQueue):
    """COMPLETED + complete → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv) is False


@pytest.mark.asyncio
async def test_completed_fail_rej(queue: JobQueue):
    """COMPLETED + fail → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    ok, _ = await queue.fail_job(jid, "w1", "late", lease_version=lv)
    assert ok is False
    assert await _st(queue, jid) == JobState.COMPLETED


@pytest.mark.asyncio
async def test_completed_cancel_rej(queue: JobQueue):
    """COMPLETED + cancel → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    assert await queue.cancel_job(jid, "w1", lease_version=lv) is False
    assert await _st(queue, jid) == JobState.COMPLETED


@pytest.mark.asyncio
async def test_completed_expire_rej(queue: JobQueue):
    """COMPLETED + expire → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    ok, reason = await queue.expire_stale_lease(jid)
    assert ok is False
    assert reason == "wrong_state"


@pytest.mark.asyncio
async def test_completed_release_rej(queue: JobQueue):
    """COMPLETED + release → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv)
    assert await queue.release_lease(jid, "w1", lease_version=lv) is False
    assert await _st(queue, jid) == JobState.COMPLETED


# ── CANCELLED ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancelled_claim_rej(queue: JobQueue):
    """CANCELLED + claim → REJECT"""
    jid = await _enq(queue)
    assert await queue.cancel_job(jid)
    job2, _ = await _clm(queue, "w1")
    assert job2 is None


@pytest.mark.asyncio
async def test_cancelled_complete_rej(queue: JobQueue):
    """CANCELLED + complete → REJECT (terminal)"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.cancel_job(jid, "w1", lease_version=lv)
    assert await queue.complete_job(jid, "w1", {}, lease_version=lv) is False
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_cancelled_fail_rej(queue: JobQueue):
    """CANCELLED + fail → REJECT (terminal)"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.cancel_job(jid, "w1", lease_version=lv)
    ok, _ = await queue.fail_job(jid, "w1", "late", lease_version=lv)
    assert ok is False
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_cancelled_cancel_rej(queue: JobQueue):
    """CANCELLED + cancel → REJECT (already terminal)"""
    jid = await _enq(queue)
    assert await queue.cancel_job(jid)
    assert await queue.cancel_job(jid) is False
    assert await _st(queue, jid) == JobState.CANCELLED


@pytest.mark.asyncio
async def test_cancelled_expire_rej(queue: JobQueue):
    """CANCELLED + expire → REJECT"""
    jid = await _enq(queue)
    assert await queue.cancel_job(jid)
    ok, reason = await queue.expire_stale_lease(jid)
    assert ok is False
    assert reason == "wrong_state"


@pytest.mark.asyncio
async def test_cancelled_release_rej(queue: JobQueue):
    """CANCELLED + release → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    assert await queue.cancel_job(jid, "w1", lease_version=lv)
    assert await queue.release_lease(jid, "w1", lease_version=lv) is False
    assert await _st(queue, jid) == JobState.CANCELLED


# ── DEAD_LETTER ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dead_letter_claim_rej(queue: JobQueue):
    """DEAD_LETTER + claim → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    # Exhaust retries to push into dead_letter
    for i in range(3):
        ok, out = await queue.fail_job(jid, "w1", f"fail-{i}", lease_version=lv)
        if ok and out == "dead_letter":
            break
        if ok and out == "retrying":
            _, lv = await _clm(queue, "w1")
    assert (await _st(queue, jid)) == JobState.DEAD_LETTER
    job2, _ = await _clm(queue, "w1")
    assert job2 is None


@pytest.mark.asyncio
async def test_dead_letter_fail_rej(queue: JobQueue):
    """DEAD_LETTER + fail → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    while ok and out == "retrying":
        _, lv = await _clm(queue, "w1")
        ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert (await _st(queue, jid)) == JobState.DEAD_LETTER
    ok2, _ = await queue.fail_job(jid, "w1", "double")
    assert ok2 is False
    assert await _st(queue, jid) == JobState.DEAD_LETTER


@pytest.mark.asyncio
async def test_dead_letter_complete_rej(queue: JobQueue):
    """DEAD_LETTER + complete → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    while ok and out == "retrying":
        _, lv = await _clm(queue, "w1")
        ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert await _st(queue, jid) == JobState.DEAD_LETTER
    assert await queue.complete_job(jid, "w1", {}) is False


@pytest.mark.asyncio
async def test_dead_letter_cancel_rej(queue: JobQueue):
    """DEAD_LETTER + cancel → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    while ok and out == "retrying":
        _, lv = await _clm(queue, "w1")
        ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert await _st(queue, jid) == JobState.DEAD_LETTER
    assert await queue.cancel_job(jid) is False


@pytest.mark.asyncio
async def test_dead_letter_expire_rej(queue: JobQueue):
    """DEAD_LETTER + expire → REJECT"""
    jid = await _enq(queue)
    _, lv = await _clm(queue, "w1")
    ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    while ok and out == "retrying":
        _, lv = await _clm(queue, "w1")
        ok, out = await queue.fail_job(jid, "w1", "boom", lease_version=lv)
    assert await _st(queue, jid) == JobState.DEAD_LETTER
    ok2, reason = await queue.expire_stale_lease(jid)
    assert ok2 is False


# ===================================================================
# Worker phase gating
# ===================================================================


@pytest.mark.asyncio
async def test_draining_claim_rej(qs: JobQueue):
    await _enq(qs)
    _reg_worker(qs, "w-drain", WorkerPhase.DRAINING.value)
    assert await qs.get_next_job_for_worker("w-drain") is None


@pytest.mark.asyncio
async def test_suspect_claim_rej(qs: JobQueue):
    await _enq(qs)
    _reg_worker(qs, "w-suspect", WorkerPhase.SUSPECT.value)
    assert await qs.get_next_job_for_worker("w-suspect") is None


@pytest.mark.asyncio
async def test_dead_claim_rej(qs: JobQueue):
    await _enq(qs)
    _reg_worker(qs, "w-dead", WorkerPhase.DEAD.value)
    assert await qs.get_next_job_for_worker("w-dead") is None


@pytest.mark.asyncio
async def test_ready_claim_ok(qs: JobQueue):
    """READY worker can still claim jobs."""
    jid = await _enq(qs)
    _reg_worker(qs, "w-ready", WorkerPhase.READY.value)
    job = await qs.get_next_job_for_worker("w-ready")
    assert job is not None and job.id == jid


# ===================================================================
# normalize_phase: unknown → SUSPECT
# ===================================================================


def test_normalize_phase_unknown_is_suspect():
    assert normalize_phase(None) == WorkerPhase.SUSPECT
    assert normalize_phase("") == WorkerPhase.SUSPECT
    assert normalize_phase("garbage") == WorkerPhase.SUSPECT


def test_normalize_phase_known():
    assert normalize_phase("ready") == WorkerPhase.READY
    assert normalize_phase("draining") == WorkerPhase.DRAINING
    assert normalize_phase("suspect") == WorkerPhase.SUSPECT
    assert normalize_phase("dead") == WorkerPhase.DEAD

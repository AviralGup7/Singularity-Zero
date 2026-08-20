"""Distributed worker trust boundary: S-2, S-6, R1-5.

A owns Job X
    Worker B: release / complete / fail  → REJECT
    Worker A: release / complete / fail  → SUCCESS

unknown / empty / garbage phase          → SUSPECT

two coordinator sweeps of the same job   → ONE reassignment
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from src.infrastructure.queue.coordinator import WorkerCoordinator
from src.infrastructure.queue.fallback_emulator import FallbackEmulator
from src.infrastructure.queue.lease_ownership import reject_if_not_owner
from src.infrastructure.queue.lua_scripts import (
    COMPLETE_JOB_SCRIPT,
    FAIL_JOB_SCRIPT,
    RELEASE_LEASE_SCRIPT,
)
from src.infrastructure.queue.models import WorkerInfo
from src.infrastructure.queue.worker_phase import WorkerPhase, normalize_phase


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return "" if value is None else str(value)


class _MemDB:
    def __init__(self) -> None:
        self.data: dict[str, tuple[str, object]] = {}

    def db_get(self, key: str) -> tuple[str | None, object]:
        return self.data.get(key, (None, None))

    def db_set(self, key: str, val_type: str, data: object) -> None:
        self.data[key] = (val_type, data)

    def db_del(self, key: str) -> int:
        return int(self.data.pop(key, None) is not None)

    def db_scan(self) -> list[str]:
        return list(self.data)


class _Bridge:
    def __init__(self) -> None:
        self.emu: FallbackEmulator | None = None

    def execute_command(self, command: str, *args: object, **kwargs: object) -> object:
        assert self.emu is not None
        return self.emu.fallback_command(command, *args, **kwargs)


def _lease_store() -> FallbackEmulator:
    bridge = _Bridge()
    emu = FallbackEmulator(
        client=bridge,
        fallback_db=_MemDB(),
        fallback_lock=threading.Lock(),
        scripts={},
    )
    bridge.emu = emu
    return emu


def _seed_owned_job(emu: FallbackEmulator, *, job_key: str = "job:x", owner: str = "A") -> None:
    emu.fallback_command(
        "HSET",
        job_key,
        mapping={
            "state": "claimed",
            "worker_id": owner,
            "lease_version": "v1",
            "bid_score": "1",
            "retries": "0",
        },
    )
    emu.fallback_command("SADD", f"worker:{owner}:jobs", job_key)


@pytest.mark.unit
def test_lua_scripts_require_caller_worker_id() -> None:
    for script in (COMPLETE_JOB_SCRIPT, FAIL_JOB_SCRIPT, RELEASE_LEASE_SCRIPT):
        assert "worker_mismatch" in script
        assert "worker_id" in script
        assert "current_worker ~= " in script


@pytest.mark.unit
def test_empty_caller_never_matches_owner() -> None:
    assert reject_if_not_owner("A", "") == "worker_mismatch"
    assert reject_if_not_owner("A", None) == "worker_mismatch"
    assert reject_if_not_owner("A", "B") == "worker_mismatch"
    assert reject_if_not_owner("A", "A") is None


@pytest.mark.unit
def test_owner_a_release_succeeds_stranger_b_rejected() -> None:
    emu = _lease_store()
    _seed_owned_job(emu)

    stolen = emu.fallback_script_exec(
        "release_lease",
        ["job:x", "worker:B:jobs", "queue"],
        ["B", "v1"],
    )
    assert int(stolen[0]) == 0
    assert _decode(stolen[1]) == "worker_mismatch"
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "claimed"
    assert _decode(emu.fallback_command("HGET", "job:x", "worker_id")) == "A"

    ok = emu.fallback_script_exec(
        "release_lease",
        ["job:x", "worker:A:jobs", "queue"],
        ["A", "v1"],
    )
    assert int(ok[0]) == 1
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "pending"
    assert _decode(emu.fallback_command("HGET", "job:x", "worker_id")) == ""


@pytest.mark.unit
def test_owner_a_complete_succeeds_stranger_b_rejected() -> None:
    emu = _lease_store()
    _seed_owned_job(emu)

    stolen = emu.fallback_script_exec(
        "complete_job",
        ["job:x", "worker:B:jobs", "metrics"],
        ["B", "{}", "1"],
    )
    assert int(stolen[0]) == 0
    assert _decode(stolen[1]) == "worker_mismatch"
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "claimed"

    ok = emu.fallback_script_exec(
        "complete_job",
        ["job:x", "worker:A:jobs", "metrics"],
        ["A", '{"ok":true}', "1"],
    )
    assert int(ok[0]) == 1
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "completed"
    assert _decode(emu.fallback_command("HGET", "job:x", "worker_id")) == ""


@pytest.mark.unit
def test_owner_a_fail_succeeds_stranger_b_rejected() -> None:
    emu = _lease_store()
    _seed_owned_job(emu)

    stolen = emu.fallback_script_exec(
        "fail_job",
        ["job:x", "worker:B:jobs", "queue", "dlq", "metrics"],
        ["B", "boom", "3", "10", "1", "2", "30"],
    )
    assert int(stolen[0]) == 0
    assert _decode(stolen[1]) == "worker_mismatch"
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "claimed"
    assert _decode(emu.fallback_command("HGET", "job:x", "worker_id")) == "A"

    ok = emu.fallback_script_exec(
        "fail_job",
        ["job:x", "worker:A:jobs", "queue", "dlq", "metrics"],
        ["A", "boom", "3", "10", "1", "2", "30"],
    )
    assert int(ok[0]) == 1
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "retrying"
    assert _decode(emu.fallback_command("HGET", "job:x", "worker_id")) == ""


@pytest.mark.unit
def test_empty_caller_cannot_release_complete_or_fail() -> None:
    emu = _lease_store()
    _seed_owned_job(emu)

    for name, keys, args in (
        ("release_lease", ["job:x", "worker:A:jobs", "queue"], ["", "v1"]),
        ("complete_job", ["job:x", "worker:A:jobs", "metrics"], ["", "{}", "1"]),
        (
            "fail_job",
            ["job:x", "worker:A:jobs", "queue", "dlq", "metrics"],
            ["", "x", "3", "1", "1", "2", "3"],
        ),
    ):
        ret = emu.fallback_script_exec(name, keys, args)
        assert int(ret[0]) == 0
        assert _decode(ret[1]) == "worker_mismatch"
    assert _decode(emu.fallback_command("HGET", "job:x", "state")) == "claimed"


@pytest.mark.unit
def test_unknown_and_dead_phases_are_suspect_not_ready() -> None:
    assert normalize_phase("unknown") is WorkerPhase.SUSPECT
    assert normalize_phase("zombie") is WorkerPhase.SUSPECT
    assert normalize_phase("") is WorkerPhase.SUSPECT
    assert normalize_phase(None) is WorkerPhase.SUSPECT
    assert normalize_phase("ready") is WorkerPhase.READY
    assert normalize_phase("idle") is WorkerPhase.READY


@pytest.mark.unit
def test_unknown_phase_worker_is_not_treated_as_healthy() -> None:
    now = 1_000.0
    worker = WorkerInfo(
        id="w-zombie",
        status="idle",
        phase="unknown",
        last_heartbeat=now - 10,
        active_jobs=["job-x"],
    )
    assert normalize_phase(worker.phase) is WorkerPhase.SUSPECT

    class _Queue:
        def __init__(self) -> None:
            self.workers = {worker.id: worker}
            self.released: list[tuple[str, str]] = []

        async def _list_workers(self) -> list[WorkerInfo]:
            return list(self.workers.values())

        async def release_lease(
            self, job_id: str, worker_id: str, lease_version: str | None = None
        ) -> bool:
            self.released.append((job_id, worker_id))
            return True

        def persist_worker(self, item: WorkerInfo) -> None:
            self.workers[item.id] = item

    queue = _Queue()
    coordinator = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)

    async def _run() -> None:
        report = await coordinator.sweep()
        assert report.declared_dead == []
        rec = coordinator.membership.get("w-zombie")
        assert rec is not None
        assert rec.status == "suspect"
        assert queue.workers["w-zombie"].phase == "suspect"

    asyncio.run(_run())


class _OwningQueue:
    """In-memory queue that rejects non-owners and second releases."""

    def __init__(self, workers: list[WorkerInfo]) -> None:
        self.workers = {item.id: item for item in workers}
        self.owners: dict[str, str] = {
            job_id: item.id for item in workers for job_id in item.active_jobs
        }
        self.released: list[tuple[str, str]] = []

    async def _list_workers(self) -> list[WorkerInfo]:
        return [item.model_copy(deep=True) for item in self.workers.values()]

    async def release_lease(
        self, job_id: str, worker_id: str, lease_version: str | None = None
    ) -> bool:
        owner = self.owners.get(job_id)
        if owner is None or owner != worker_id:
            return False
        del self.owners[job_id]
        self.released.append((job_id, worker_id))
        return True

    def persist_worker(self, worker: WorkerInfo) -> None:
        self.workers[worker.id] = worker


@pytest.mark.unit
def test_two_coordinator_sweeps_one_reassignment() -> None:
    now = 2_000.0
    worker = WorkerInfo(
        id="w-dead",
        status="dead",
        phase="dead",
        last_heartbeat=now - 120,
        active_jobs=["job-x"],
    )
    queue = _OwningQueue([worker])
    first = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)
    second = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)

    async def _run() -> None:
        left, right = await asyncio.gather(first.sweep(), second.sweep())
        successes = [item for item in (*left.reassigned, *right.reassigned) if item.released]
        assert len(successes) == 1
        assert successes[0].job_id == "job-x"
        assert queue.released == [("job-x", "w-dead")]

    asyncio.run(_run())


@pytest.mark.unit
def test_same_coordinator_concurrent_sweeps_one_reassignment() -> None:
    now = 3_000.0
    worker = WorkerInfo(
        id="w-dead",
        status="dead",
        phase="dead",
        last_heartbeat=now - 120,
        active_jobs=["job-x"],
    )
    queue = _OwningQueue([worker])
    coordinator = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)

    async def _run() -> None:
        left, right = await asyncio.gather(coordinator.sweep(), coordinator.sweep())
        successes = [item for item in (*left.reassigned, *right.reassigned) if item.released]
        assert len(successes) == 1
        assert queue.released == [("job-x", "w-dead")]

    asyncio.run(_run())

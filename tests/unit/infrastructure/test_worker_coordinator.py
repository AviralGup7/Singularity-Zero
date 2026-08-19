"""Worker lifecycle + coordinator reassignment (no Redis)."""

from __future__ import annotations

import time

import pytest

from src.infrastructure.queue.coordinator import WorkerCoordinator
from src.infrastructure.queue.models import WorkerInfo
from src.infrastructure.queue.worker_phase import WorkerPhase, normalize_phase


class _FakeQueue:
    def __init__(self, workers: list[WorkerInfo]) -> None:
        self.workers = {w.id: w for w in workers}
        self.released: list[tuple[str, str]] = []
        self.persisted: list[str] = []

    async def _list_workers(self) -> list[WorkerInfo]:
        return list(self.workers.values())

    async def release_lease(self, job_id: str, worker_id: str,
                            lease_version: str | None = None) -> bool:
        self.released.append((job_id, worker_id))
        return True

    def persist_worker(self, worker: WorkerInfo) -> None:
        self.workers[worker.id] = worker
        self.persisted.append(worker.id)


@pytest.mark.unit
def test_normalize_legacy_status() -> None:
    assert normalize_phase("idle") is WorkerPhase.READY
    assert normalize_phase("busy") is WorkerPhase.RUNNING
    assert normalize_phase("shutting_down") is WorkerPhase.DRAINING
    assert normalize_phase("dead") is WorkerPhase.DEAD
    assert normalize_phase("suspect") is WorkerPhase.SUSPECT


@pytest.mark.unit
def test_worker_info_roundtrip_preserves_phase() -> None:
    info = WorkerInfo(id="w1", status="busy", phase="running", active_jobs=["j1"])
    restored = WorkerInfo.from_redis_hash(info.to_redis_hash())
    assert restored.phase == "running"
    assert restored.status == "busy"
    assert restored.active_jobs == ["j1"]


@pytest.mark.unit
def test_sweep_marks_silent_worker_suspect() -> None:
    now = 1_000.0
    worker = WorkerInfo(
        id="w-silent",
        status="busy",
        phase="running",
        last_heartbeat=now - 50,
        active_jobs=["job-a"],
    )
    queue = _FakeQueue([worker])
    coordinator = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)

    async def _run() -> None:
        report = await coordinator.sweep()
        assert report.suspected == ["w-silent"]
        assert report.declared_dead == []
        assert queue.workers["w-silent"].phase == "suspect"

    import asyncio

    asyncio.run(_run())


@pytest.mark.unit
def test_sweep_declares_dead_and_reassigns() -> None:
    now = 2_000.0
    worker = WorkerInfo(
        id="w-dead",
        status="busy",
        phase="running",
        last_heartbeat=now - 120,
        active_jobs=["job-1", "run-abc"],
        metadata={"job_run_ids": {"job-1": "run-from-meta"}},
    )
    queue = _FakeQueue([worker])
    recovered: list[str] = []

    async def _recover(run_id: str) -> None:
        recovered.append(run_id)

    coordinator = WorkerCoordinator(
        queue,
        suspect_after=45,
        dead_after=90,
        clock=lambda: now,
        recover_run=_recover,
    )

    async def _run() -> None:
        report = await coordinator.sweep()
        assert report.declared_dead == ["w-dead"]
        assert {item.job_id for item in report.reassigned} == {"job-1", "run-abc"}
        assert all(item.released for item in report.reassigned)
        assert queue.released == [("job-1", "w-dead"), ("run-abc", "w-dead")]
        assert queue.workers["w-dead"].phase == "dead"
        assert queue.workers["w-dead"].active_jobs == []
        assert "run-from-meta" in report.unfinished_run_ids
        assert "run-abc" in report.unfinished_run_ids
        assert recovered == ["run-from-meta", "run-abc"]

    import asyncio

    asyncio.run(_run())


@pytest.mark.unit
def test_suspect_then_dead_on_second_sweep() -> None:
    clock = {"now": 100.0}
    worker = WorkerInfo(
        id="w2",
        phase="running",
        last_heartbeat=50.0,
        active_jobs=["j"],
    )
    queue = _FakeQueue([worker])
    coordinator = WorkerCoordinator(
        queue, suspect_after=40, dead_after=80, clock=lambda: clock["now"]
    )

    async def _run() -> None:
        first = await coordinator.sweep()
        assert first.suspected == ["w2"]
        assert queue.workers["w2"].phase == "suspect"
        clock["now"] = 140.0
        second = await coordinator.sweep()
        assert second.declared_dead == ["w2"]
        assert [item.job_id for item in second.reassigned] == ["j"]

    import asyncio

    asyncio.run(_run())


@pytest.mark.unit
def test_draining_worker_not_killed_while_heartbeating() -> None:
    now = time.time()
    worker = WorkerInfo(
        id="w-drain",
        status="shutting_down",
        phase="draining",
        last_heartbeat=now - 10,
        active_jobs=["finishing"],
    )
    queue = _FakeQueue([worker])
    coordinator = WorkerCoordinator(queue, suspect_after=45, dead_after=90, clock=lambda: now)

    async def _run() -> None:
        report = await coordinator.sweep()
        assert report.declared_dead == []
        assert report.suspected == []
        assert queue.workers["w-drain"].phase == "draining"

    import asyncio

    asyncio.run(_run())

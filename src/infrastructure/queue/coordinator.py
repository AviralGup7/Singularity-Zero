"""Coordinator: detect dead workers and reassign their unfinished work.

Once local checkpoint+WAL recovery is reliable, the mesh has to answer
\"what happens when worker 7 disappears halfway through a 6-hour scan?\"

This coordinator is that answer:

1. Watch heartbeats.
2. Mark silent workers SUSPECT, then DEAD after a confirmation window.
3. Release their leases so a live worker can claim the jobs.
4. Surface unfinished pipeline run IDs so Recovery Manager can resume.

The sweep is serialized by an asyncio lock so two concurrent sweeps
cannot release the same lease twice, and each lease release carries
a CAS token (lease_version) so even a stale sweep cannot release a
lease that a live worker has since re-acquired.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.models import WorkerInfo
from src.infrastructure.queue.worker_phase import (
    WorkerPhase,
    legacy_status,
    normalize_phase,
)

logger = get_pipeline_logger(__name__)


class QueueForCoordinator(Protocol):
    """Minimal queue surface the coordinator needs."""

    async def _list_workers(self) -> list[WorkerInfo]: ...

    async def release_lease(
        self, job_id: str, worker_id: str, lease_version: str | None = None
    ) -> bool: ...

    def persist_worker(self, worker: WorkerInfo) -> None: ...


@dataclass
class Reassignment:
    """One job taken off a dead worker and put back on the queue."""

    worker_id: str
    job_id: str
    released: bool
    run_id: str | None = None


@dataclass
class SweepReport:
    """Result of one coordinator pass over the worker set."""

    inspected: int = 0
    suspected: list[str] = field(default_factory=list)
    declared_dead: list[str] = field(default_factory=list)
    reassigned: list[Reassignment] = field(default_factory=list)
    unfinished_run_ids: list[str] = field(default_factory=list)


class WorkerCoordinator:
    """Fault-tolerance loop: heartbeat → suspect → dead → reassign.

    Sweep is serialized by ``_sweep_lock`` so overlapping calls never
    evaluate the same worker twice.  Lease releases use CAS (lease_version)
    so a stale sweep cannot steal a lease from a worker that re-acquired it.
    """

    def __init__(
        self,
        queue: QueueForCoordinator,
        *,
        suspect_after: float = 45.0,
        dead_after: float = 90.0,
        clock: Callable[[], float] = time.time,
        persist: Callable[[WorkerInfo], None] | None = None,
        recover_run: Callable[[str], Awaitable[Any]] | None = None,
    ) -> None:
        if dead_after < suspect_after:
            raise ValueError("dead_after must be >= suspect_after")
        self.queue = queue
        self.suspect_after = suspect_after
        self.dead_after = dead_after
        self._clock = clock
        self._persist = persist or getattr(queue, "persist_worker", None)
        self._recover_run = recover_run
        self._sweep_lock = asyncio.Lock()

    async def sweep(self) -> SweepReport:
        """Inspect every registered worker and act on missing heartbeats.

        Safe to call concurrently — overlapping sweeps are serialized
        by an internal lock so no worker is inspected twice.
        """
        async with self._sweep_lock:
            return await self._sweep_once()

    async def _sweep_once(self) -> SweepReport:
        report = SweepReport()
        workers = await self.queue._list_workers()
        report.inspected = len(workers)
        now = self._clock()
        for worker in workers:
            await self._evaluate_worker(worker, now, report)
        return report

    async def _evaluate_worker(self, worker: WorkerInfo, now: float, report: SweepReport) -> None:
        phase = normalize_phase(getattr(worker, "phase", None) or worker.status)
        age = now - float(worker.last_heartbeat or 0.0)
        if phase is WorkerPhase.DEAD:
            await self._reassign(worker, report)
            return
        if phase is WorkerPhase.DRAINING:
            # Graceful drain is allowed to finish; only promote if the
            # heartbeat also timed out (worker crashed mid-drain).
            if age >= self.dead_after:
                await self._declare_dead(worker, report)
            return
        if age >= self.dead_after or (phase is WorkerPhase.SUSPECT and age >= self.suspect_after):
            await self._declare_dead(worker, report)
            return
        if age >= self.suspect_after and phase is not WorkerPhase.SUSPECT:
            self._mark(worker, WorkerPhase.SUSPECT)
            report.suspected.append(worker.id)
            logger.warning(
                "Coordinator: worker %s SUSPECT (heartbeat age=%.1fs)",
                worker.id,
                age,
            )

    async def _declare_dead(self, worker: WorkerInfo, report: SweepReport) -> None:
        self._mark(worker, WorkerPhase.DEAD)
        report.declared_dead.append(worker.id)
        logger.error("Coordinator: worker %s DEAD — reassigning unfinished work", worker.id)
        await self._reassign(worker, report)

    async def _reassign(self, worker: WorkerInfo, report: SweepReport) -> None:
        for job_id in list(worker.active_jobs or []):
            run_id = _run_id_from_job(job_id, worker)
            # Look up the most recent known lease_version for this job.
            # If the worker was declared dead the version comes from
            # the coordinator's last-known worker state.  If a live
            # worker has since claimed the job its lease_version
            # won't match and release_lease will safely no-op.
            lease_version = _lease_version_for_job(job_id, worker)
            released = False
            try:
                released = await self.queue.release_lease(
                    job_id,
                    worker.id,
                    lease_version=lease_version,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Coordinator: release_lease failed worker=%s job=%s: %s",
                    worker.id,
                    job_id,
                    exc,
                )
            report.reassigned.append(
                Reassignment(
                    worker_id=worker.id,
                    job_id=job_id,
                    released=released,
                    run_id=run_id,
                )
            )
            if run_id:
                report.unfinished_run_ids.append(run_id)
                if self._recover_run is not None:
                    try:
                        await self._recover_run(run_id)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Coordinator: Recovery Manager failed for run %s: %s",
                            run_id,
                            exc,
                        )
        worker.active_jobs = []
        self._write(worker)

    def _mark(self, worker: WorkerInfo, phase: WorkerPhase) -> None:
        worker.phase = phase.value
        worker.status = legacy_status(phase)
        self._write(worker)

    def _write(self, worker: WorkerInfo) -> None:
        if self._persist is None:
            return
        try:
            self._persist(worker)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Coordinator: persist worker %s failed: %s", worker.id, exc)


def _run_id_from_job(job_id: str, worker: WorkerInfo) -> str | None:
    metadata = worker.metadata or {}
    runs = metadata.get("job_run_ids")
    if isinstance(runs, dict):
        value = runs.get(job_id)
        if value:
            return str(value)
    if isinstance(job_id, str) and job_id.startswith("run-"):
        return job_id
    return None


def _lease_version_for_job(job_id: str, worker: WorkerInfo) -> str | None:
    """Return the last-known lease_version for *job_id* from worker metadata."""
    metadata = worker.metadata or {}
    leases = metadata.get("lease_versions")
    if isinstance(leases, dict):
        return str(leases.get(job_id, "")) or None
    return None

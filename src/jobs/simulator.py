"""Deterministic pipeline simulator for tests and local demos."""

from __future__ import annotations

from src.jobs.stages import STAGE_ORDER, StageKey, StageStatus
from src.jobs.status import JobStatus
from src.jobs.store import MemoryJobStore


class PipelineSimulator:
    def __init__(self, store: MemoryJobStore | None = None) -> None:
        self.store = store if store is not None else MemoryJobStore()

    def run(
        self,
        *,
        base_url: str,
        fail_at: str | None = None,
        skip: frozenset[str] | None = None,
        findings: int = 0,
    ) -> str:
        job = self.store.create(base_url=base_url)
        job_id = str(job["id"])
        self.store.transition(job_id, JobStatus.RUNNING)
        skip_set = skip or frozenset()
        for stage in STAGE_ORDER:
            if stage in {StageKey.STARTUP, StageKey.COMPLETED}:
                continue
            if stage.value in skip_set:
                self.store.update_stage(job_id, stage, StageStatus.SKIPPED, reason="simulator")
                continue
            if fail_at == stage.value:
                self.store.update_stage(
                    job_id, stage, StageStatus.FAILED, error="simulated failure"
                )
                self.store.finish(job_id, returncode=1, stderr=f"{stage.value} failed")
                return job_id
            self.store.update_stage(job_id, stage, StageStatus.RUNNING, processed=1, total=1)
            self.store.update_stage(
                job_id, stage, StageStatus.COMPLETED, processed=1, total=1, percent=100
            )
        current = self.store.get(job_id)
        if current is not None:
            current["findings_count"] = findings
            self.store.put(current)
        self.store.finish(job_id, returncode=0)
        return job_id

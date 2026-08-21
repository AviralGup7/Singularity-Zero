"""Job store metrics for the ops dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.jobs.status import JobStatus, parse_job_status
from src.jobs.store import MemoryJobStore


@dataclass
class JobMetrics:
    created: int = 0
    completed: int = 0
    failed: int = 0
    stopped: int = 0
    findings: int = 0
    durations: list[float] = field(default_factory=list)

    def observe(self, store: MemoryJobStore) -> None:
        self.created = len(store)
        self.completed = 0
        self.failed = 0
        self.stopped = 0
        self.findings = 0
        self.durations = []
        for job in store.list():
            status = parse_job_status(job.get("status"))
            if status is JobStatus.COMPLETED:
                self.completed += 1
            elif status is JobStatus.FAILED:
                self.failed += 1
            elif status is JobStatus.STOPPED:
                self.stopped += 1
            self.findings += int(job.get("findings_count", 0) or 0)
            started = job.get("started_at")
            finished = job.get("finished_at")
            if isinstance(started, (int, float)) and isinstance(finished, (int, float)):
                self.durations.append(max(0.0, float(finished) - float(started)))

    @property
    def success_rate(self) -> float:
        terminal = self.completed + self.failed + self.stopped
        if not terminal:
            return 0.0
        return round(self.completed / terminal, 3)

    @property
    def avg_duration(self) -> float:
        if not self.durations:
            return 0.0
        return round(sum(self.durations) / len(self.durations), 3)

    def to_dict(self) -> dict[str, object]:
        return {
            "created": self.created,
            "completed": self.completed,
            "failed": self.failed,
            "stopped": self.stopped,
            "findings": self.findings,
            "success_rate": self.success_rate,
            "avg_duration": self.avg_duration,
        }

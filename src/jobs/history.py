"""Rolling history of finished jobs for trend views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.jobs.status import JobStatus, parse_job_status
from src.jobs.store import MemoryJobStore


@dataclass
class HistoryPoint:
    job_id: str
    status: str
    duration: float
    findings: int
    hostname: str

    def to_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "duration": self.duration,
            "findings": self.findings,
            "hostname": self.hostname,
        }


@dataclass
class JobHistory:
    points: list[HistoryPoint] = field(default_factory=list)

    def ingest(self, store: MemoryJobStore) -> None:
        self.points.clear()
        for job in store.list():
            status = parse_job_status(job.get("status"))
            if status not in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.STOPPED}:
                continue
            started = float(job.get("started_at") or 0)
            finished = float(job.get("finished_at") or started)
            self.points.append(
                HistoryPoint(
                    job_id=str(job.get("id") or ""),
                    status=status.value,
                    duration=max(0.0, finished - started),
                    findings=int(job.get("findings_count") or 0),
                    hostname=str(job.get("hostname") or ""),
                )
            )

    def mean_duration(self) -> float:
        if not self.points:
            return 0.0
        return round(sum(item.duration for item in self.points) / len(self.points), 3)

    def findings_total(self) -> int:
        return sum(item.findings for item in self.points)

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.points),
            "mean_duration": self.mean_duration(),
            "findings_total": self.findings_total(),
            "points": [item.to_dict() for item in self.points],
        }

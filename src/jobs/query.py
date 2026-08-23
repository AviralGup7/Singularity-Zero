"""Filter / sort / page job records without FastAPI."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from src.jobs.status import (
    JobStatus,
    is_active_job_status,
    is_terminal_job_status,
    parse_job_status,
)


@dataclass(frozen=True, slots=True)
class JobFilter:
    status: str | None = None
    hostname: str | None = None
    mode: str | None = None
    active_only: bool = False
    terminal_only: bool = False
    stalled: bool | None = None
    search: str | None = None
    min_findings: int | None = None


@dataclass(frozen=True, slots=True)
class Page:
    items: list[dict[str, Any]]
    total: int
    offset: int
    limit: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


def _matches(job: dict[str, Any], spec: JobFilter) -> bool:
    if spec.status and parse_job_status(job.get("status")) is not parse_job_status(spec.status):
        return False
    if spec.active_only and not is_active_job_status(job.get("status")):
        return False
    if spec.terminal_only and not is_terminal_job_status(job.get("status")):
        return False
    if spec.hostname and spec.hostname.lower() not in str(job.get("hostname") or "").lower():
        return False
    if spec.mode and str(job.get("mode") or "").lower() != spec.mode.lower():
        return False
    if spec.min_findings is not None and int(job.get("findings_count", 0) or 0) < spec.min_findings:
        return False
    if spec.search:
        blob = " ".join(
            [
                str(job.get("id") or ""),
                str(job.get("hostname") or ""),
                str(job.get("base_url") or ""),
                str(job.get("target_name") or ""),
                str(job.get("mode") or ""),
            ]
        ).lower()
        if spec.search.lower() not in blob:
            return False
    return True


def filter_jobs(
    jobs: Iterable[dict[str, Any]], spec: JobFilter | None = None
) -> list[dict[str, Any]]:
    query = spec or JobFilter()
    return [job for job in jobs if _matches(job, query)]


def sort_jobs(
    jobs: Sequence[dict[str, Any]],
    *,
    key: str = "updated_at",
    reverse: bool = True,
) -> list[dict[str, Any]]:
    def _value(job: dict[str, Any]) -> float | str:
        raw = job.get(key)
        if raw is None:
            return 0
        if isinstance(raw, (int, float)):
            return float(raw)
        return str(raw)

    return sorted(jobs, key=_value, reverse=reverse)


def paginate(jobs: Sequence[dict[str, Any]], *, offset: int = 0, limit: int = 50) -> Page:
    start = max(0, int(offset))
    size = min(max(1, int(limit)), 500)
    return Page(items=list(jobs[start : start + size]), total=len(jobs), offset=start, limit=size)


def counts_by_status(jobs: Iterable[dict[str, Any]]) -> dict[str, int]:
    tallies = {status.value: 0 for status in JobStatus}
    for job in jobs:
        status = parse_job_status(job.get("status")).value
        tallies[status] = tallies.get(status, 0) + 1
    return tallies

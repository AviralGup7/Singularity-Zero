"""Extra job list presets used by the console."""

from __future__ import annotations

from src.jobs.query import JobFilter
from src.jobs.status import JobStatus


def failed() -> JobFilter:
    return JobFilter(status=JobStatus.FAILED.value, terminal_only=True)


def running() -> JobFilter:
    return JobFilter(active_only=True)


def high_yield(*, min_findings: int = 5) -> JobFilter:
    return JobFilter(min_findings=min_findings)


def for_host(hostname: str) -> JobFilter:
    return JobFilter(hostname=hostname)

"""One-line console status for operators."""

from __future__ import annotations

from src.console.runtime import ConsoleRuntime
from src.jobs.labels import findings_tone, status_tone


def line(runtime: ConsoleRuntime, *, now: float) -> str:
    snap = runtime.snapshot(now=now)
    jobs = snap["jobs"]
    notifs = snap["notifications"]
    return (
        f"jobs={jobs['total']} running={jobs['running']} failed={jobs['failed']} "
        f"unread={notifs['unread']} sessions={snap['sessions']}"
    )


def tones(runtime: ConsoleRuntime, *, now: float) -> dict[str, str]:
    snap = runtime.snapshot(now=now)
    jobs = snap["jobs"]
    failed = int(jobs["failed"])
    return {
        "jobs": status_tone("failed" if failed else "completed"),
        "findings": findings_tone(int(jobs.get("total") or 0)),
    }

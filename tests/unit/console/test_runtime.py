from __future__ import annotations

from src.console import ConsoleRuntime
from src.jobs import JobStatus


def test_console_demo_scan_completes() -> None:
    runtime = ConsoleRuntime()
    subject = runtime.sign_in_demo("Ada")
    assert subject
    job_id = runtime.run_scan("https://app.test", findings=2)
    job = runtime.store.get(job_id)
    assert job is not None
    assert job["status"] == JobStatus.COMPLETED.value
    snap = runtime.snapshot(now=job["started_at"] + 10)
    assert snap["jobs"]["total"] == 1


def test_console_failed_scan_notifies() -> None:
    runtime = ConsoleRuntime()
    runtime.run_scan("https://bad.test", fail_at="active_scan")
    assert len(runtime.inbox) >= 1

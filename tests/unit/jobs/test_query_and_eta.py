from __future__ import annotations

from src.jobs import JobFilter, create_job_record, elapsed_seconds, filter_jobs, format_duration, paginate, remaining_seconds, stalled, sort_jobs
from src.jobs.eta import remaining_seconds as eta_remaining
from src.jobs.status import JobStatus, _transition


def test_filter_search_and_paginate() -> None:
    jobs = [
        create_job_record(base_url="https://a.example", hostname="a.example", mode_name="idor"),
        create_job_record(base_url="https://b.example", hostname="b.example", mode_name="ssrf"),
    ]
    _transition(jobs[0], JobStatus.RUNNING)
    jobs[0]["findings_count"] = 4
    found = filter_jobs(jobs, JobFilter(search="b.example"))
    assert len(found) == 1
    ranked = sort_jobs(jobs, key="hostname", reverse=False)
    assert ranked[0]["hostname"] == "a.example"
    page = paginate(jobs, offset=1, limit=1)
    assert page.total == 2
    assert page.has_more is False


def test_eta_and_stalled() -> None:
    job = create_job_record(base_url="https://app.test", now=1000.0)
    _transition(job, JobStatus.RUNNING)
    job["progress_percent"] = 20
    job["updated_at"] = 1000.0
    remaining = remaining_seconds(job, now=1100.0)
    assert remaining is not None and remaining > 0
    assert format_duration(65).endswith("s")
    assert stalled(job, now=1300.0, after_seconds=180) is True
    assert elapsed_seconds(job, now=1100.0) == 100.0
    assert eta_remaining(job, now=1100.0) == remaining

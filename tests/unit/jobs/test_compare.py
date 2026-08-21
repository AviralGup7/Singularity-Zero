from __future__ import annotations

from src.jobs.compare import diff_jobs, improved
from src.jobs.records import create_job_record


def test_diff_detects_more_findings() -> None:
    left = create_job_record(base_url="https://a.test")
    right = create_job_record(base_url="https://a.test")
    left["findings_count"] = 4
    right["findings_count"] = 1
    right["critical_findings"] = 0
    left["critical_findings"] = 2
    delta = diff_jobs(left, right)
    assert delta["findings_delta"] == -3
    assert improved(delta)

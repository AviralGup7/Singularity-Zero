from __future__ import annotations

from src.jobs import MemoryJobStore, StageStatus, merge_timelines, overall_percent, running_stage_count
from src.jobs.status import JobStatus


def test_progress_updates_timeline() -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://app.test")
    store.transition(job["id"], JobStatus.RUNNING)
    store.update_stage(job["id"], "subdomains", StageStatus.COMPLETED, processed=10, total=10, percent=12)
    store.update_stage(job["id"], "live_hosts", StageStatus.RUNNING, processed=1, total=4)
    current = store.get(job["id"])
    assert current is not None
    assert running_stage_count(current) >= 1
    assert overall_percent(current) >= 12
    merged = merge_timelines(current, store.events)
    stages = {row["stage"] for row in merged["stages"]}
    assert "subdomains" in stages
    assert merged["events"]

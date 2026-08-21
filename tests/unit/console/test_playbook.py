from __future__ import annotations

from src.console.playbook import playbook, run_playbook
from src.jobs.store import MemoryJobStore


def test_playbook_runs() -> None:
    store = MemoryJobStore()
    job_id = run_playbook(store, "https://pb.test", "standard")
    assert store.get(job_id) is not None
    assert playbook("idor").fail_fast is True

from __future__ import annotations

import pytest

from src.jobs import JobStatus, MemoryJobStore, create_job_record
from src.jobs.schema import JobSchemaError, require_valid, validate_job
from src.notifications import Inbox
from src.notifications.bridge import connect


def test_valid_record_passes() -> None:
    job = create_job_record(base_url="https://ok.test")
    assert validate_job(job) == []
    require_valid(job)


def test_invalid_record_raises() -> None:
    with pytest.raises(JobSchemaError):
        require_valid({"id": ""})


def test_bridge_emits_failure_notification() -> None:
    store = MemoryJobStore()
    inbox = Inbox()
    connect(store, inbox)
    job = store.create(base_url="https://x.test")
    store.transition(job["id"], JobStatus.RUNNING)
    store.finish(job["id"], returncode=2, stderr="fatal: pipeline failed")
    assert len(inbox) >= 1

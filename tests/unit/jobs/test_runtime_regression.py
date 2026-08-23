"""Regression coverage for the job runtime built during the liner pass."""

from __future__ import annotations

import pytest

from src.jobs import (
    FailureCode,
    JobFilter,
    JobStatus,
    MemoryJobStore,
    StageKey,
    StageStatus,
    classify_failure,
    create_job_record,
    parse_job_status,
)
from src.jobs.failure import apply_exit
from src.jobs.stages import next_stage, parse_stage_key, previous_stages, stage_band_percent


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("queued", JobStatus.PENDING),
        ("in_progress", JobStatus.RUNNING),
        ("cancelled", JobStatus.STOPPED),
        ("error", JobStatus.FAILED),
        ("completed", JobStatus.COMPLETED),
    ],
)
def test_status_aliases(raw: str, expected: JobStatus) -> None:
    assert parse_job_status(raw) is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("recon", StageKey.SUBDOMAINS),
        ("passive", StageKey.PASSIVE_SCAN),
        ("active", StageKey.ACTIVE_SCAN),
        ("report", StageKey.REPORTING),
        ("done", StageKey.COMPLETED),
    ],
)
def test_stage_aliases(raw: str, expected: StageKey) -> None:
    assert parse_stage_key(raw) is expected


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("timed out waiting", FailureCode.TIMEOUT),
        ("429 too many requests", FailureCode.RATE_LIMIT),
        ("recon_validation failed", FailureCode.RECON),
        ("global_deadline_exceeded", FailureCode.BUDGET),
        ("econnrefused", FailureCode.NETWORK),
        ("stop requested by user", FailureCode.CANCELLED),
        ("wasm trap", FailureCode.SANDBOX),
        ("something else", FailureCode.UNKNOWN),
    ],
)
def test_failure_markers(text: str, code: FailureCode) -> None:
    assert classify_failure(text).code is code


def test_stage_band_and_neighbors() -> None:
    assert 4 <= stage_band_percent("subdomains", 0.0) <= 12
    assert next_stage("startup") is StageKey.SUBDOMAINS
    assert StageKey.STARTUP in previous_stages("urls")
    assert next_stage("completed") is None


def test_store_search_mode_and_drop() -> None:
    store = MemoryJobStore()
    a = store.create(base_url="https://a.test", mode_name="idor", hostname="a.test")
    b = store.create(base_url="https://b.test", mode_name="ssrf", hostname="b.test")
    store.transition(a["id"], JobStatus.RUNNING)
    store.finish(b["id"], returncode=0)
    idor = store.list(JobFilter(mode="idor"))
    assert len(idor) == 1
    search = store.list(JobFilter(search="b.test"))
    assert search[0]["id"] == b["id"]
    dropped = store.drop_terminal()
    assert dropped == 1
    assert store.get(b["id"]) is None


def test_apply_exit_nonzero() -> None:
    job = create_job_record(base_url="https://z.test")
    apply_exit(job, returncode=2, stderr="fatal: pipeline failed\n")
    assert job["status"] == JobStatus.FAILED.value
    assert job["stderr_fatal_lines"]


def test_heartbeat_updates_version() -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://h.test")
    version = job["state_version"]
    store.heartbeat(job["id"])
    again = store.get(job["id"])
    assert again is not None
    assert again["state_version"] >= version


@pytest.mark.parametrize("percent", [0, 1, 20, 50, 99])
def test_progress_never_decreases(percent: int) -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://p.test")
    store.transition(job["id"], JobStatus.RUNNING)
    store.update_stage(job["id"], "urls", StageStatus.RUNNING, percent=percent)
    current = store.get(job["id"])
    assert current is not None
    assert current["progress_percent"] >= min(percent, current["progress_percent"])

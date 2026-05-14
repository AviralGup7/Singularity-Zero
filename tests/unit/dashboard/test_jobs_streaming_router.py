import pytest

from src.dashboard.fastapi.config import FeatureFlags
from src.dashboard.fastapi.routers import jobs as jobs_router


class _FakeRequest:
    def __init__(self) -> None:
        self.headers = {}
        self._checks = 0

    async def is_disconnected(self) -> bool:
        self._checks += 1
        return self._checks > 1


class _FakeServices:
    def __init__(self, job: dict[str, object]) -> None:
        self._job = job

    def get_job(self, _job_id: str) -> dict[str, object]:
        return self._job


def _running_job(stage: str = "live_hosts") -> dict[str, object]:
    return {
        "id": "job-stream-test",
        "status": "running",
        "stage": stage,
        "progress_percent": 36,
        "status_message": "Probing live hosts",
        "latest_logs": [],
        "stage_processed": None,
        "stage_total": None,
        "iteration": 0,
        "max_iterations": 0,
        "started_at": 0.0,
        "updated_at": 0.0,
        "failed_stage": "",
        "failure_reason_code": "",
        "failure_step": "",
        "failure_reason": "",
    }


@pytest.mark.asyncio
async def test_stream_job_progress_heartbeat_interval_is_numeric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(FeatureFlags, "ENABLE_SSE_PROGRESS", classmethod(lambda cls: True))
    monkeypatch.setattr(
        FeatureFlags,
        "SSE_HEARTBEAT_INTERVAL_SECONDS",
        classmethod(lambda cls: 25),
    )

    response = await jobs_router.stream_job_progress(
        "job-stream-test",
        _FakeRequest(),
        _auth=None,
        services=_FakeServices(_running_job()),
    )

    chunk = await response.body_iterator.__anext__()
    text = chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk)
    assert "event: progress_update" in text


@pytest.mark.asyncio
async def test_stream_job_logs_typed_stream_heartbeat_interval_is_numeric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(FeatureFlags, "ENABLE_SSE_PROGRESS", classmethod(lambda cls: True))
    monkeypatch.setattr(
        FeatureFlags,
        "SSE_HEARTBEAT_INTERVAL_SECONDS",
        classmethod(lambda cls: 25),
    )

    response = await jobs_router.stream_job_logs(
        "job-stream-test",
        _FakeRequest(),
        _auth=None,
        services=_FakeServices(_running_job(stage="subdomains")),
    )

    chunk = await response.body_iterator.__anext__()
    text = chunk.decode("utf-8") if isinstance(chunk, bytes) else str(chunk)
    assert "event: progress_update" in text

import pytest
from collections.abc import Generator
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
)


@pytest.fixture(autouse=True)
def reset_global_tracker() -> Generator[None]:
    """Reset the global sequence tracker before each test."""
    _global_tracker._counters.clear()
    yield


@pytest.fixture
def emitter() -> SSEEventEmitter:
    """Return an SSEEventEmitter for a test job."""
    return SSEEventEmitter(job_id="test-job-001")

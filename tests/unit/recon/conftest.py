"""Conftest for unit/recon tests.

Auto-resets the global collector health registry before each test so a
stale ``SKIPPED_CIRCUIT_OPEN`` state from a previous (possibly
network-flaky) test run cannot short-circuit providers in unrelated
unit tests.  This keeps the test environment hermetic without
requiring every test to call :func:`reset_health_state` explicitly.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_collector_health(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the health registry at a per-test temp file and clear it.

    Two pieces:

    1. Override ``COLLECTOR_HEALTH_STATE_PATH`` so the per-test registry
       writes to a private file (so parallel test workers don't clobber
       each other).
    2. Reset the in-memory state via :func:`reset_health_state` so any
       previously persisted state in the user cache directory cannot
       affect the current test.
    """
    from src.recon.collectors import health

    tmp_path = Path(tempfile.gettempdir()) / "cyber-pipeline-tests-collector-health.json"
    if tmp_path.exists():
        try:
            tmp_path.unlink()
        except OSError:
            pass
    monkeypatch.setenv("COLLECTOR_HEALTH_STATE_PATH", str(tmp_path))
    # Force the registry to re-resolve its state path after the env change.
    health.HEALTH_REGISTRY._state_path = None  # noqa: SLF001
    health.HEALTH_REGISTRY._loaded = False  # noqa: SLF001
    health.reset_health_state()


@pytest.fixture
def isolated_health_state_path(tmp_path: Path) -> Path:
    """Return a temp path suitable for passing to a fresh ``ProviderHealthRegistry``."""
    return tmp_path / "collector_health.json"


# Make sure pytest's tmp_path is available even if upstream conftest
# changes — we declare the dependency up-front.
_ = os.environ.get("PYTEST_CURRENT_TEST")

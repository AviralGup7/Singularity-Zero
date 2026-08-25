"""Fixtures for dashboard unit tests that hit FastAPI learning-router endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from httpx._transports.asgi import ASGITransport

from src.dashboard.fastapi.routers.learning import router as learning_router
from src.learning.integration import LearningIntegration
from src.learning.telemetry_store import TelemetryStore


@pytest.fixture
def learning_db(tmp_path: Path) -> TelemetryStore:
    """Provide an initialized TelemetryStore backed by a temporary SQLite file."""
    db_path = tmp_path / "telemetry.db"
    store = TelemetryStore(db_path)
    store.initialize()
    yield store
    store.close()


@pytest.fixture
def learning_db_path(tmp_path: Path) -> Path:
    """Provide a path to a temporary, unopened SQLite file."""
    return tmp_path / "telemetry.db"


@pytest.fixture
async def learning_integration(
    learning_db: TelemetryStore,
    request: pytest.FixtureRequest,
) -> LearningIntegration:
    """Provide a LearningIntegration wired to the test store.

    Accepts an optional ``learning_target`` mark so tests can set a named
    target that is forwarded to the integration context via
    ``ctx = {"target_name": <target>}``.
    """
    LearningIntegration.reset()
    target: str | None = None
    mark = request.node.get_closest_marker("learning_target")
    if mark and mark.args:
        target = str(mark.args[0])
    integration = LearningIntegration.get_or_create(
        ctx={"target_name": target} if target else {},
    )
    return integration


def _noop_lifespan(app: Any) -> Any:
    """No-op lifespan context manager — skips all startup/shutdown work."""
    yield


@pytest.fixture
def asyncio_lifespan_off(tmp_path: Path) -> Any:
    """Return a factory that builds a FastAPI app with the lifespan disabled.

    Each call creates an *independent* FastAPI instance so unit tests can
    mutate ``dependency_overrides`` and ``state`` freely between cases.

    ``httpx.AsyncClient`` with ``ASGITransport`` is used in the actual
    test helper so lifespan messages are never sent to the ASGI callable.
    """
    _counter = [0]

    def _factory() -> Any:
        app: Any = FastAPI(lifespan=_noop_lifespan)
        app.include_router(learning_router, prefix="")
        _counter[0] += 1
        return app

    return _factory


@pytest.fixture
async def async_learning_client(  # noqa: B008
    learning_db: TelemetryStore,
) -> Any:
    """Provide an ``httpx.AsyncClient`` connected to the learning ASGI app.

    ``ASGITransport`` does not send ``lifespan.startup``/
    ``lifespan.shutdown`` messages, so no background services are started –
    equivalent to ``asyncio_lifespan_off`` semantics.

    Pre-populates any data already stored in *learning_db*.
    """
    LearningIntegration.reset()
    app: Any = FastAPI()
    app.include_router(learning_router, prefix="")

    # Make the router use the in-memory test store rather than its own
    # on-disk singleton so every test starts from a clean, known state.
    def _dep() -> Any:  # noqa: S603
        return LearningIntegration.get_or_create(ctx={})

    from src.dashboard.fastapi.dependencies import get_learning_integration

    app.dependency_overrides[get_learning_integration] = _dep

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(  # noqa: S603
        transport=transport,
        base_url="http://test",
    ) as client:
        try:
            yield client
        finally:
            LearningIntegration.reset()

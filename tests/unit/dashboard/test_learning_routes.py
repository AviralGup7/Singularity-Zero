"""Unit tests for the FastAPI learning-router endpoints (Phase 5.3).

Tests use ``asyncio_lifespan_off`` — a factory fixture that builds a bare
FastAPI app with the learning router registered and the lifespan mechanism
disabled, then drives it with an ``httpx.AsyncClient`` over ``ASGITransport``.

A fresh ``LearningIntegration`` is wired in per-test case via
``app.dependency_overrides`` so every test starts from a clean, isolated store.

Following the task spec (Phase 5.3):
- GET /api/learning/kpis  →  LearningIntegration.get_kpis → PipelineKPIs.to_dict
- GET /api/learning/feedback  →  TelemetryStore.get_feedback_events / get_feedback_events_for_run
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from httpx._transports.asgi import ASGITransport

from src.dashboard.fastapi.dependencies import get_learning_integration, require_auth
from src.dashboard.fastapi.routers.learning import router as learning_router
from src.learning.integration import LearningIntegration
from src.learning.telemetry_store import TelemetryStore


def _noop_lifespan(app: Any) -> Any:
    """No-op lifespan context manager — skips all startup/shutdown work."""
    yield


def _build_learning_app(
    store: TelemetryStore,
    target: str | None = None,
) -> tuple[FastAPI, httpx.AsyncClient]:
    """Return (app, client) with the learning dependency resolved to a fresh store.

    ``target`` is forwarded to the integration context so that
    ``/api/learning/kpis?target=...`` is exercised with the matching ctx entry.
    """
    app = FastAPI(lifespan=_noop_lifespan)
    app.include_router(learning_router, prefix="")

    LearningIntegration.reset()

    def _get_dep() -> LearningIntegration:  # noqa: S603
        return LearningIntegration.get_or_create(ctx={"target_name": target} if target else {})

    # Monkey-patch the store in so the integration points at the temp DB
    dep = _get_dep()
    dep.store = store

    app.dependency_overrides[get_learning_integration] = _get_dep
    # Learning endpoints are gated by ``require_auth`` in the router. The
    # test suite exercises the response shape, not the auth contract, so
    # we override the dependency to return ``None`` (an unauthenticated
    # principal) so the request reaches the handler.
    app.dependency_overrides[require_auth] = lambda: None

    transport = ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")  # noqa: S603
    return app, client


def _populate_feedback(
    store: TelemetryStore,
    run_id: str = "run-1",
    count: int = 1,
) -> None:
    """Insert *count* synthetic feedback-event rows directly into *store*.

    Uses the underlying SQLite connection so we can supply only the columns
    we care about without tripping over every named bind-parameter in the
    full schema.

    Inserts the ``run_id`` into ``scan_runs`` first to satisfy the FK
    constraint on ``feedback_events.run_id`` → ``scan_runs.run_id``.
    """
    conn = store._get_conn()
    # Insert a minimal scan_runs row so the FK on feedback_events is satisfied.
    conn.execute(
        "INSERT OR REPLACE INTO scan_runs (run_id, target_name, mode, start_time, status) "
        "VALUES (?, ?, ?, ?, ?)",
        (run_id, "test.example.com", "deep", "2025-06-01T00:00:00+00:00", "completed"),
    )
    for i in range(count):
        conn.execute(
            "INSERT INTO feedback_events "
            "(event_id, run_id, timestamp, target_host, target_endpoint, "
            "finding_category, finding_severity, finding_confidence, "
            "finding_decision, plugin_name, parameter_name, parameter_type, "
            "was_validated, was_false_positive, scan_mode, feedback_weight) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"evt-{run_id}-{i}",
                run_id,
                "2025-06-01T00:00:00+00:00",
                "test.example.com",
                f"/api/endpoint/{i}",
                "auth",
                "medium",
                0.8,
                "KEEP",
                "test-plugin",
                f"param_{i}",
                "query",
                1,
                0,
                "deep",
                0.0,
            ),
        )
    conn.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kpis_endpoint_returns_dict_with_required_keys(
    asyncio_lifespan_off: Any,
    learning_db: TelemetryStore,
) -> None:
    """GET /api/learning/kpis → dict containing 'precision', 'recall', 'fp_rate'."""
    app, client = _build_learning_app(learning_db)
    try:
        resp = await client.get("/api/learning/kpis")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, dict)
        assert "precision" in body
        assert "recall" in body
        assert "fp_rate" in body
    finally:
        await client.aclose()
        LearningIntegration.reset()


@pytest.mark.asyncio
async def test_feedback_endpoint_returns_list(
    asyncio_lifespan_off: Any,
    learning_db: TelemetryStore,
) -> None:
    """GET /api/learning/feedback → list (possibly empty when DB is warm)."""
    app, client = _build_learning_app(learning_db)
    try:
        resp = await client.get("/api/learning/feedback")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
    finally:
        await client.aclose()
        LearningIntegration.reset()


@pytest.mark.asyncio
async def test_feedback_endpoint_respects_limit(
    asyncio_lifespan_off: Any,
    learning_db: TelemetryStore,
) -> None:
    """GET /api/learning/feedback?limit=5 → list length ≤ 5."""
    _populate_feedback(learning_db, run_id="run-limit", count=20)

    app, client = _build_learning_app(learning_db)
    try:
        resp = await client.get("/api/learning/feedback", params={"limit": 5})
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        assert len(body) <= 5
    finally:
        await client.aclose()
        LearningIntegration.reset()


@pytest.mark.asyncio
async def test_feedback_endpoint_filters_by_run_id(
    asyncio_lifespan_off: Any,
    learning_db: TelemetryStore,
) -> None:
    """GET /api/learning/feedback?run_id=<id> → only matching rows returned."""
    _populate_feedback(learning_db, run_id="run-abc", count=5)
    _populate_feedback(learning_db, run_id="run-xyz", count=3)

    app, client = _build_learning_app(learning_db)
    try:
        resp = await client.get(
            "/api/learning/feedback",
            params={"run_id": "run-abc"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        for row in body:
            assert row.get("run_id") == "run-abc"
    finally:
        await client.aclose()
        LearningIntegration.reset()


@pytest.mark.asyncio
async def test_kpis_with_named_target(
    asyncio_lifespan_off: Any,
    learning_db: TelemetryStore,
) -> None:
    """GET /api/learning/kpis?target=test.example returns a valid KPI dict."""
    app, client = _build_learning_app(learning_db, target="test.example")
    try:
        resp = await client.get("/api/learning/kpis", params={"target": "test.example"})
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, dict)
        assert "precision" in body
        assert "fp_rate" in body
    finally:
        await client.aclose()
        LearningIntegration.reset()

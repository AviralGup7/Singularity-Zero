"""Align HTTP/WS/recon metrics with the observability catalog (cyber_pipeline_ prefix)."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.infrastructure.observability.cardinality import DB_OPERATIONS
from src.infrastructure.observability.metrics import get_metrics, reset_metrics_instance


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    reset_metrics_instance()
    yield
    reset_metrics_instance()


def test_db_operations_allowlist_pins_unknown_to_other() -> None:
    assert DB_OPERATIONS.get("select") == "select"
    assert DB_OPERATIONS.get("insert") == "insert"
    assert DB_OPERATIONS.get("update") == "update"
    assert DB_OPERATIONS.get("delete") == "delete"
    assert DB_OPERATIONS.get("ddl") == "ddl"
    assert DB_OPERATIONS.get("other") == "other"
    assert DB_OPERATIONS.get("truncate") == "other"
    assert DB_OPERATIONS.cardinality == 6


def test_http_in_flight_inc_and_dec() -> None:
    from src.dashboard.fastapi.http_metrics import HTTPMetricsMiddleware

    async def homepage(request):  # type: ignore[no-untyped-def]
        inflight = get_metrics().gauge("http_requests_in_flight", labels={"method": "GET"})
        assert inflight.get() >= 1
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(HTTPMetricsMiddleware)
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert get_metrics().gauge("http_requests_in_flight", labels={"method": "GET"}).get() == 0
    names = get_metrics().get_all()
    assert any(k.startswith("cyber_pipeline_http_requests_total") for k in names["counters"])
    assert any(k.startswith("cyber_pipeline_http_request_duration_seconds") for k in names["histograms"])


def test_websocket_metrics_use_registry_prefix() -> None:
    from src.websocket_server.metrics import WS_CONNECTIONS, WS_DROPPED_MESSAGES, WS_MESSAGES

    WS_CONNECTIONS.inc()
    WS_MESSAGES.labels(scope="group").inc()
    WS_DROPPED_MESSAGES.labels(scope="group").inc()
    data = get_metrics().get_all()
    assert data["gauges"]["cyber_pipeline_ws_active_connections"] == 1
    assert any(k.startswith("cyber_pipeline_ws_messages_broadcast_total") for k in data["counters"])
    assert any(k.startswith("cyber_pipeline_ws_dropped_messages_total") for k in data["counters"])


def test_recon_metrics_use_registry_prefix_and_urls_counter() -> None:
    from src.recon.collectors.metrics import (
        increment_errors,
        increment_requests,
        increment_urls,
        observe_duration,
    )

    increment_requests("wayback")
    increment_errors("wayback")
    increment_urls("wayback", 3)
    observe_duration("wayback", 0.25)
    data = get_metrics().get_all()
    assert any(k.startswith("cyber_pipeline_recon_provider_requests_total") for k in data["counters"])
    assert any(k.startswith("cyber_pipeline_recon_provider_errors_total") for k in data["counters"])
    assert any(k.startswith("cyber_pipeline_recon_provider_urls_total") for k in data["counters"])
    assert any(k.startswith("cyber_pipeline_recon_provider_duration_seconds") for k in data["histograms"])

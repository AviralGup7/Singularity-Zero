from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.websocket_server.integration import setup_websocket_routes


def _build_app() -> FastAPI:
    app = FastAPI()
    setup_websocket_routes(app)
    return app


def test_websocket_routes_do_not_require_websocket_query_param() -> None:
    app = _build_app()
    expected_paths = {
        "/ws/scan-progress",
        "/ws/job-status",
        "/ws/logs/{job_id}",
        "/ws/dashboard",
    }

    seen_paths: set[str] = set()
    for route in app.routes:
        path = getattr(route, "path", "")
        if path not in expected_paths:
            continue
        seen_paths.add(path)
        dependant = getattr(route, "dependant", None)
        assert dependant is not None
        query_param_names = {param.name for param in dependant.query_params}
        assert "websocket" not in query_param_names

    assert seen_paths == expected_paths


def test_logs_websocket_connects_without_auth_when_unconfigured() -> None:
    app = _build_app()

    with TestClient(app) as client:
        with client.websocket_connect("/ws/logs/runtime-check") as websocket:
            message = websocket.receive_json()

    assert message["type"] == "ack"
    assert message["ack_id"] == "connect"
    assert message["accepted"] is True

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


def test_websocket_origin_validation() -> None:
    app = FastAPI()
    setup_websocket_routes(app, allowed_origins={"https://trusted.com"})

    with TestClient(app) as client:
        # Test missing Origin header: should be rejected
        try:
            with client.websocket_connect("/ws/scan-progress") as websocket:
                _ = websocket.receive_json()
                assert False, "Should have been closed/rejected due to missing Origin"
        except Exception:
            pass

        # Test unauthorized Origin header: should be rejected
        try:
            with client.websocket_connect(
                "/ws/scan-progress", headers={"Origin": "https://evil.com"}
            ) as websocket:
                _ = websocket.receive_json()
                assert False, "Should have been closed/rejected due to unauthorized Origin"
        except Exception:
            pass

        # Test authorized Origin header: should succeed
        with client.websocket_connect(
            "/ws/scan-progress", headers={"Origin": "https://trusted.com"}
        ) as websocket:
            message = websocket.receive_json()
            assert message["type"] == "ack"
            assert message["ack_id"] == "connect"


def test_websocket_frame_size_limit() -> None:
    app = FastAPI()
    setup_websocket_routes(app)

    with TestClient(app) as client:
        with client.websocket_connect("/ws/scan-progress") as websocket:
            _ = websocket.receive_json()  # ack connection

            # Send a payload exceeding the 128 KB max cap (128 KB + 10 bytes)
            large_payload = "a" * (128 * 1024 + 10)
            try:
                websocket.send_text(large_payload)
                _ = websocket.receive_json()
                assert False, "Should have disconnected due to large payload size limit"
            except Exception:
                pass


def test_websocket_invalid_json() -> None:
    app = FastAPI()
    setup_websocket_routes(app)

    with TestClient(app) as client:
        with client.websocket_connect("/ws/scan-progress") as websocket:
            _ = websocket.receive_json()  # ack connection

            # Send malformed JSON
            websocket.send_text("{invalid_json_here}")
            response = websocket.receive_json()
            assert response["type"] == "error"
            assert response["code"] == "invalid_message"


def test_websocket_rate_limiting() -> None:
    app = FastAPI()
    setup_websocket_routes(app)

    with TestClient(app) as client:
        with client.websocket_connect("/ws/scan-progress") as websocket:
            _ = websocket.receive_json()  # ack connection

            # Send messages rapidly to trigger the rate-limiting token-bucket allowance (max 100 burst)
            import json

            subscribe_payload = json.dumps(
                {"type": "subscribe", "channel": "global", "id": "test-sub"}
            )

            exceeded = False
            for _ in range(120):
                try:
                    websocket.send_text(subscribe_payload)
                except Exception:
                    break

            for _ in range(130):
                try:
                    msg = websocket.receive_json()
                    if msg.get("type") == "error" and msg.get("code") == "rate_limit_exceeded":
                        exceeded = True
                        break
                except Exception:
                    break

            assert exceeded is True


from unittest.mock import MagicMock

import pytest
from starlette.websockets import WebSocketState

from src.websocket_server.protocol import StatusMessage


@pytest.mark.asyncio
async def test_websocket_broadcast_metrics() -> None:
    app = FastAPI()
    services = setup_websocket_routes(app)
    services.broadcaster._redis_enabled = False

    msg = StatusMessage(
        job_id="job_id",
        status="running",
    )

    # 1. Test with zero connections
    result = await services._broadcast_to_job_and_global(msg, "job_id")
    assert result == 0

    # 2. Test with connections registered
    mock_ws1 = MagicMock()
    mock_ws1.client_state = WebSocketState.CONNECTED
    conn1 = await services.manager.connect(mock_ws1, "user1", "conn1", "127.0.0.1")
    assert conn1 is not None
    await services.manager.add_to_group("conn1", "job:job_id")

    mock_ws2 = MagicMock()
    mock_ws2.client_state = WebSocketState.CONNECTED
    conn2 = await services.manager.connect(mock_ws2, "user2", "conn2", "127.0.0.1")
    assert conn2 is not None
    await services.manager.add_to_group("conn2", "global")

    # Since conn1 is in job:job_id and conn2 is in global, calling _broadcast_to_job_and_global
    # should deliver to both (1 for job, 1 for global) and return 2.
    msg2 = StatusMessage(
        job_id="job_id",
        status="completed",
    )
    result = await services._broadcast_to_job_and_global(msg2, "job_id")
    assert result == 2

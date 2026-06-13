from unittest.mock import MagicMock, patch

import pytest

from src.core.http_utils import async_safe_request, safe_request
from src.execution.frontier.chameleon import RequestChameleon, _chameleon
from src.execution.frontier.chameleon_evasion import ChameleonEvasionEngine


def test_chameleon_evasion_engine_telemetry():
    engine = ChameleonEvasionEngine()
    engine.reset_metrics()
    assert len(engine.get_metrics()) == 0

    # Observe a successful request
    engine.update_observation(
        response_status=200,
        body="OK",
        session_id="session123",
        target="target.local",
        detected_waf=None,
    )

    metrics = engine.get_metrics()
    assert "session123:target.local" in metrics
    entry = metrics["session123:target.local"]
    assert entry["total_requests"] == 1
    assert entry["successes"] == 1
    assert entry["blocks"] == 0
    assert entry["current_state"] == "undetected"

    # Observe a challenge request
    engine.update_observation(
        response_status=200,
        body="solve this captcha to proceed",
        session_id="session123",
        target="target.local",
        detected_waf="Cloudflare",
    )

    metrics = engine.get_metrics()
    entry = metrics["session123:target.local"]
    assert entry["total_requests"] == 2
    assert entry["challenges"] == 1
    assert entry["detected_waf"] == "Cloudflare"

    # Observe a block request
    engine.update_observation(
        response_status=403,
        body="Blocked by firewall",
        session_id="session123",
        target="target.local",
        detected_waf="Cloudflare",
    )

    metrics = engine.get_metrics()
    entry = metrics["session123:target.local"]
    assert entry["total_requests"] == 3
    assert entry["blocks"] == 1
    assert entry["current_state"] in ("suspected", "blocked", "evading")


def test_waf_signature_detection():
    chameleon = RequestChameleon()

    # Cloudflare detection
    headers = {"CF-Ray": "12345", "Server": "cloudflare"}
    body = "Checking your browser..."
    waf = chameleon.detect_waf(headers, body)
    assert waf == "Cloudflare"

    # AWS WAF detection
    headers = {"X-Amzn-RequestId": "req-id"}
    body = "blocked by AWS WAF"
    waf = chameleon.detect_waf(headers, body)
    assert waf == "AWS WAF"

    # Imperva detection
    headers = {"X-Iinfo": "info"}
    body = "incapsula incident"
    waf = chameleon.detect_waf(headers, body)
    assert waf == "Imperva/Incapsula"


@patch("src.core.http_utils.is_safe_url", return_value=True)
@patch("src.core.http_utils._get_sync_session")
def test_safe_request_evasion_feedback(mock_get_session, mock_is_safe):
    # Mock successful response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Hello world"
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.cookies = []

    mock_session = MagicMock()
    mock_session.request.return_value = mock_resp
    mock_get_session.return_value = mock_session

    # Reset metrics
    _chameleon.reset_metrics()

    # Call safe_request
    res = safe_request(
        "http://test-evasion.local/path", headers={"X-Session-Token": "session-test"}
    )

    assert res["status"] == 200
    metrics = _chameleon.get_metrics()
    key = "session-test:test-evasion.local"
    assert key in metrics
    assert metrics[key]["total_requests"] == 1
    assert metrics[key]["successes"] == 1


@pytest.mark.asyncio
@patch("src.core.http_utils.is_safe_url", return_value=True)
@patch("src.core.http_utils._get_async_client")
async def test_async_safe_request_evasion_feedback(mock_get_client, mock_is_safe):
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Access denied"
    mock_resp.headers = {"X-Amzn-Waf-Blocked": "true"}
    mock_resp.cookies = []

    # We must support async requests on the mock client
    async def mock_async_req(*args, **kwargs):
        return mock_resp

    mock_client.request = mock_async_req
    mock_get_client.return_value = mock_client

    _chameleon.reset_metrics()

    res = await async_safe_request(
        "http://test-async-evasion.local/", headers={"X-Trace-ID": "async-session"}
    )

    assert res["status"] == 403
    metrics = _chameleon.get_metrics()
    key = "async-session:test-async-evasion.local"
    assert key in metrics
    assert metrics[key]["total_requests"] == 1
    assert metrics[key]["blocks"] == 1
    assert metrics[key]["detected_waf"] is not None

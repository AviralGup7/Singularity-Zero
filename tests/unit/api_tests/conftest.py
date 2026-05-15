from typing import Any

import pytest

from src.api_tests.apitester.models import (
    ApiTestContext,
    ComparisonSummary,
    RequestSummary,
)


@pytest.fixture
def sample_api_key() -> str:
    return "sk-test-abc123def456ghi789"


@pytest.fixture
def sample_base_url() -> str:
    return "https://api.example.com"


@pytest.fixture
def sample_test_item() -> dict[str, Any]:
    return {
        "title": "Potential IDOR",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "request_context": {
            "baseline_url": "https://api.example.com/users/123",
            "mutated_url": "https://api.example.com/users/456",
            "parameter": "user_id",
            "variant": "456",
            "method": "GET",
        },
        "evidence": {
            "diff_summary": {
                "status_changed": True,
                "redirect_changed": False,
                "content_changed": True,
                "body_similarity": 0.45,
                "length_delta": 1200,
            },
            "shared_key_fields": ["user_id", "email", "name"],
            "mutated_url": "https://api.example.com/users/456",
        },
        "replay_id": "replay-001",
    }


@pytest.fixture
def minimal_test_item() -> dict[str, Any]:
    return {
        "title": "Minimal Test",
        "request_context": {
            "baseline_url": "https://api.example.com/baseline",
            "mutated_url": "https://api.example.com/variant",
            "method": "POST",
        },
    }


@pytest.fixture
def empty_context_item() -> dict[str, Any]:
    return {"title": "Empty Context"}


@pytest.fixture
def mock_response_200() -> Any:
    class FakeResponse:
        status_code = 200
        text = '{"status": "ok", "data": []}'
        headers = {"content-type": "application/json"}
        url = "https://api.example.com/users/me"

    return FakeResponse()


@pytest.fixture
def mock_response_403() -> Any:
    class FakeResponse:
        status_code = 403
        text = '{"error": "forbidden"}'
        headers = {"content-type": "application/json"}
        url = "https://api.example.com/admin"

    return FakeResponse()


@pytest.fixture
def mock_response_404() -> Any:
    class FakeResponse:
        status_code = 404
        text = '{"error": "not found"}'
        headers = {"content-type": "application/json"}
        url = "https://api.example.com/missing"

    return FakeResponse()


@pytest.fixture
def mock_session() -> Any:
    class FakeSession:
        def __init__(self) -> None:
            self._response: Any = None
            self._error: str | None = None
            self.requests: list[tuple[str, str, dict[str, Any]]] = []

        def set_response(self, response: Any, error: str | None = None) -> None:
            self._response = response
            self._error = error

        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            params: dict[str, str] | None = None,
            cookies: dict[str, str] | None = None,
            timeout: int = 10,
            proxies: dict[str, str] | None = None,
            json: Any = None,
            allow_redirects: bool = True,
        ) -> Any:
            self.requests.append((method, url, {"headers": headers, "params": params}))
            if self._error:
                raise ConnectionError(self._error)
            return self._response

        def close(self) -> None:
            pass

        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    return FakeSession()


@pytest.fixture
def sample_workflow_spec() -> dict[str, Any]:
    return {
        "key": "advanced",
        "label": "Advanced API Key Test",
        "description": "Run the broad advanced API key coverage workflow.",
    }


@pytest.fixture
def key_location_template() -> dict[str, Any]:
    return {"name": "Header (X-API-Key)", "headers": {"X-API-Key": "{api_key}"}}


@pytest.fixture
def sample_candidate() -> dict[str, str]:
    return {
        "key_value": "sk-test-abc123def456",
        "masked_key": "sk-tes...f456",
        "source_url": "https://example.com/app.js",
        "base_url": "https://api.example.com",
        "source_type": "javascript",
        "provider": "custom",
        "placement": "header:x-api-key",
    }


@pytest.fixture
def sample_context() -> ApiTestContext:
    return ApiTestContext(
        title="Test Context",
        severity="HIGH",
        confidence="medium",
        method="GET",
        url="https://api.example.com/users/456",
        baseline_url="https://api.example.com/users/123",
        path="/users/456",
        query="",
        baseline_path="/users/123",
        baseline_query="",
        parameter="user_id",
        variant="456",
        replay_id="replay-001",
        combined_signal="idor, auth_bypass",
        next_step="Verify authorization boundary",
    )


@pytest.fixture
def sample_request_summary_ok() -> RequestSummary:
    return RequestSummary(
        ok=True,
        error="",
        status_code=200,
        content_type="application/json",
        body_length=1024,
    )


@pytest.fixture
def sample_request_summary_error() -> RequestSummary:
    return RequestSummary(
        ok=False,
        error="connection refused",
        status_code=None,
        content_type="",
        body_length=0,
    )


@pytest.fixture
def sample_comparison_summary() -> ComparisonSummary:
    return ComparisonSummary(
        status_changed=True,
        length_changed=True,
        interesting_difference=True,
    )

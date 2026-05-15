"""
Conftest for unit tests.

Provides fixtures common to all unit test categories.
"""

from typing import Any

import pytest
from tests.factories import (
    ConfigBuilder,
    FindingBuilder,
    RequestBuilder,
    ResponseBuilder,
)


@pytest.fixture
def mock_http_response() -> dict[str, Any]:
    """Return a mock HTTP response dict for testing."""
    return {
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": '{"status": "ok"}',
    }


@pytest.fixture
def mock_request() -> dict[str, Any]:
    """Return a mock request dict for testing."""
    return {
        "method": "GET",
        "url": "https://example.com/api/v1/test",
        "headers": {"Authorization": "Bearer test-token"},
    }


@pytest.fixture
def unit_config() -> dict[str, Any]:
    """Return a minimal Config dict for unit tests with low concurrency."""
    return (
        ConfigBuilder()
        .with_nuclei_workers(1)
        .with_http_workers(1)
        .with_scan_depth(1)
        .with_max_pages(10)
        .with_rate_limit(1, 2)
        .build()
    )


@pytest.fixture
def unit_response() -> dict[str, Any]:
    """Return a minimal successful response for unit tests."""
    return ResponseBuilder().with_status(200).with_body('{"ok": true}').build()


@pytest.fixture
def unit_error_response() -> dict[str, Any]:
    """Return a minimal error response for unit tests."""
    return ResponseBuilder().with_status(500).with_body('{"error": "server error"}').build()


@pytest.fixture
def unit_finding() -> dict[str, Any]:
    """Return a minimal finding for unit tests."""
    return FindingBuilder().with_id("unit-finding-001").build()


@pytest.fixture
def unit_request() -> dict[str, Any]:
    """Return a minimal request for unit tests."""
    return RequestBuilder().with_url("https://example.com/api/unit").build()

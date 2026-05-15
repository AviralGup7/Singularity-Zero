"""
Root conftest.py for the security test pipeline.

Provides shared pytest fixtures available to all test categories.
"""

import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from tests.factories import (
    ConfigBuilder,
    FindingBuilder,
    RequestBuilder,
    ResponseBuilder,
)


@pytest.fixture
def temp_workspace() -> Generator[Path]:
    """Provide a temporary workspace directory for tests."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def sample_config_json() -> str:
    """Return a minimal valid configuration JSON string."""
    return (
        '{"target_name":"example.com","output_dir":"output",'
        '"concurrency":{"nuclei_workers":2},'
        '"output":{"dedupe_aliases":true}}'
    )


@pytest.fixture
def sample_scope() -> str:
    """Return a sample scope definition."""
    return "example.com\napi.example.com"


@pytest.fixture
def sample_config() -> dict[str, Any]:
    """Return a sample Config dict built with ConfigBuilder."""
    return ConfigBuilder().build()


@pytest.fixture
def sample_finding() -> dict[str, Any]:
    """Return a sample security finding dict built with FindingBuilder."""
    return FindingBuilder().build()


@pytest.fixture
def sample_request() -> dict[str, Any]:
    """Return a sample HTTP request dict built with RequestBuilder."""
    return RequestBuilder().build()


def make_response(
    url: str, status_code: int = 200, body: str = "", headers: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Create a mock response dict for testing."""
    return {
        "url": url,
        "status_code": status_code,
        "body": body,
        "headers": headers or {},
        "response_time": 0.1,
        "redirect_chain": [],
    }


@pytest.fixture
def sample_response() -> dict[str, Any]:
    """Return a sample HTTP response dict built with ResponseBuilder."""
    return ResponseBuilder().build()


@pytest.fixture
def sample_url() -> str:
    """Return a sample URL string for testing."""
    return "https://example.com/api/v1/test"


@pytest.fixture
def response_factory() -> Any:
    """Factory fixture for creating mock response dicts."""
    return make_response

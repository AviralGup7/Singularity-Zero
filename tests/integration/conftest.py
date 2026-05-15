"""
Conftest for integration tests.

Provides fixtures for tests that span multiple modules.
"""

import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def integration_output_dir() -> Generator[Path]:
    """Provide a temporary output directory for integration tests."""
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "output"
        output_dir.mkdir()
        yield output_dir


@pytest.fixture
def full_pipeline_config() -> dict[str, Any]:
    """Return a full pipeline configuration for integration testing."""
    return {
        "target_name": "integration-test.example.com",
        "output_dir": "output",
        "scope": ["integration-test.example.com"],
        "concurrency": {"nuclei_workers": 2, "active_workers": 2},
        "output": {"dedupe_aliases": True, "write_artifact_manifest": True},
        "notifications": {"enabled": False, "channels": []},
    }

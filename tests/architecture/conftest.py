"""
Conftest for architecture tests.

Provides fixtures for architecture boundary and layer dependency tests.
"""

from pathlib import Path

import pytest


@pytest.fixture
def workspace_root() -> Path:
    """Return the workspace root directory."""
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def source_dirs(workspace_root: Path) -> list[Path]:
    """Return all source code directories to scan."""
    return [
        workspace_root / "core",
        workspace_root / "analysis",
        workspace_root / "recon",
        workspace_root / "detection",
        workspace_root / "intelligence",
        workspace_root / "decision",
        workspace_root / "execution",
        workspace_root / "reporting",
        workspace_root / "fuzzing",
        workspace_root / "plugins",
        workspace_root / "pipeline_platform",
        workspace_root / "dashboard_app",
    ]

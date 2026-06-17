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
        workspace_root / "src" / "core",
        workspace_root / "src" / "analysis",
        workspace_root / "src" / "recon",
        workspace_root / "src" / "detection",
        workspace_root / "src" / "intelligence",
        workspace_root / "src" / "decision",
        workspace_root / "src" / "execution",
        workspace_root / "src" / "reporting",
        workspace_root / "src" / "fuzzing",
        workspace_root / "src" / "plugins",
        workspace_root / "src" / "pipeline_platform",
        workspace_root / "src" / "dashboard_app",
    ]

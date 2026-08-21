"""Prime analyzer bindings so detection tests do not import analysis themselves."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session", autouse=True)
def _register_analysis_plugins() -> None:
    import src.analysis.plugin_registration  # noqa: F401

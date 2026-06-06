"""Calibration helpers for the calibrated severity model.

Extracted from ``src.intelligence.severity_model`` so that prediction /
training logic can depend on calibration without pulling in tokenisation or
feature-vector code.
"""

from __future__ import annotations

from typing import Any


DEFAULT_DB_PATH = ".pipeline/telemetry.db"
DEFAULT_ACTIVE_MODEL_VERSION = "severity-logreg-v1"


def get_default_active_version(registry: Any | None) -> str:
    """Return the registry's active ``severity_model`` version, or a default."""
    if registry is None:
        return DEFAULT_ACTIVE_MODEL_VERSION
    try:
        active = registry.get_active_model("severity_model")
    except AttributeError:
        return DEFAULT_ACTIVE_MODEL_VERSION
    if active is None:
        return DEFAULT_ACTIVE_MODEL_VERSION
    return str(active.version)


__all__ = [
    "DEFAULT_ACTIVE_MODEL_VERSION",
    "DEFAULT_DB_PATH",
    "get_default_active_version",
]

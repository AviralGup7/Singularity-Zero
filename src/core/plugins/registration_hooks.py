"""Plugin registration hooks for the core layer.

This module provides a hook-based plugin registration system that allows
higher layers (analysis, detection) to register their plugin handlers
without core needing to import from those layers.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class AnalysisPluginRegistrar(Protocol):
    """Protocol for registering analysis plugins."""

    def register_analysis_plugin(
        self,
        key: str,
        manifest: dict[str, Any],
        runner: Callable[..., Any],
        *,
        input_kind: str = "dynamic_analysis_context",
        phase: str = "discover",
        consumes: tuple[str, ...] = (),
        produces: tuple[str, ...] = (),
    ) -> None:
        """Register an analysis plugin."""
        ...

    def unregister_analysis_plugin(self, key: str) -> None:
        """Unregister an analysis plugin."""
        ...

    def invalidate_analysis_cache(self) -> None:
        """Invalidate the analysis plugin cache."""
        ...


class DetectionCacheInvalidator(Protocol):
    """Protocol for invalidating detection plugin caches."""

    def invalidate_detection_cache(self) -> None:
        """Invalidate the detection plugin cache."""
        ...


# Global registries for hooks
_analysis_registrar: AnalysisPluginRegistrar | None = None
_detection_invalidator: DetectionCacheInvalidator | None = None


def register_analysis_plugin_registrar(registrar: AnalysisPluginRegistrar) -> None:
    """Register the analysis plugin registrar hook."""
    global _analysis_registrar
    _analysis_registrar = registrar
    logger.debug("Analysis plugin registrar registered")


def register_detection_cache_invalidator(invalidator: DetectionCacheInvalidator) -> None:
    """Register the detection cache invalidator hook."""
    global _detection_invalidator
    _detection_invalidator = invalidator
    logger.debug("Detection cache invalidator registered")


def get_analysis_registrar() -> AnalysisPluginRegistrar | None:
    """Get the registered analysis plugin registrar."""
    return _analysis_registrar


def get_detection_invalidator() -> DetectionCacheInvalidator | None:
    """Get the registered detection cache invalidator."""
    return _detection_invalidator


def has_analysis_registrar() -> bool:
    """Check if an analysis plugin registrar is registered."""
    return _analysis_registrar is not None


def has_detection_invalidator() -> bool:
    """Check if a detection cache invalidator is registered."""
    return _detection_invalidator is not None

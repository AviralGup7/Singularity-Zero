"""Analysis plugin registration implementation.

This module implements the AnalysisPluginRegistrar protocol and registers
itself with core.plugins at import time.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.plugins.registration_hooks import register_analysis_plugin_registrar

logger = logging.getLogger(__name__)


class AnalysisPluginRegistrarImpl:
    """Implementation of the AnalysisPluginRegistrar protocol."""

    def register_analysis_plugin(
        self,
        key: str,
        manifest: dict[str, Any],
        runner: Any,
        *,
        input_kind: str = "dynamic_analysis_context",
        phase: str = "discover",
        consumes: tuple[str, ...] = (),
        produces: tuple[str, ...] = (),
    ) -> None:
        """Register an analysis plugin."""
        from src.analysis.plugin_runtime import ANALYZER_BINDING
        from src.analysis.plugin_runtime_models import AnalyzerBinding
        from src.analysis.plugins._main import DETECTOR_SPEC
        from src.analysis.plugins.base import spec
        from src.core.plugins.registry import register_plugin

        plugin_spec = spec(
            key,
            manifest.get("name", key),
            manifest.get("description", ""),
            manifest.get("group", "custom"),
            slug=manifest.get("slug"),
            enabled_by_default=manifest.get("enabled_by_default", True),
            source="dynamic",
        )
        register_plugin(DETECTOR_SPEC, key, manifest=manifest, dynamic=True)(plugin_spec)

        binding = AnalyzerBinding(
            input_kind=input_kind,
            runner=runner,
            phase=phase,
            consumes=consumes,
            produces=produces,
        )
        register_plugin(ANALYZER_BINDING, key, manifest=manifest, dynamic=True)(binding)

        # Update the binding cache
        try:
            from src.analysis.plugin_runtime import _bindings

            _bindings.ANALYZER_BINDINGS[key] = binding
        except Exception as exc:
            logger.debug("Unable to update analyzer binding cache for %s: %s", key, exc)

        # Invalidate detection cache
        self._invalidate_detection_cache()

    def unregister_analysis_plugin(self, key: str) -> None:
        """Unregister an analysis plugin."""
        try:
            from src.analysis.plugin_runtime import _bindings

            _bindings.ANALYZER_BINDINGS.pop(key, None)
        except Exception as exc:
            logger.debug("Unable to remove analyzer binding cache for %s: %s", key, exc)

    def invalidate_analysis_cache(self) -> None:
        """Invalidate the analysis plugin cache."""
        try:
            from src.analysis.plugins._main import invalidate_analysis_plugin_cache

            invalidate_analysis_plugin_cache()
        except Exception as exc:
            logger.debug("Unable to invalidate analysis plugin cache: %s", exc)

    def _invalidate_detection_cache(self) -> None:
        """Invalidate the detection plugin cache."""
        try:
            from src.detection import registry

            registry._DETECTION_PLUGIN_OPTIONS = None
        except Exception as exc:
            logger.debug("Unable to invalidate detection plugin cache: %s", exc)


def register_analysis_hooks() -> None:
    """Register the analysis plugin hooks with core."""
    registrar = AnalysisPluginRegistrarImpl()
    register_analysis_plugin_registrar(registrar)
    logger.debug("Analysis plugin hooks registered")


# Auto-register when imported
register_analysis_hooks()

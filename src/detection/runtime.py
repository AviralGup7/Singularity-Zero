"""Detection runtime facade delegating to the analysis layer.

Provides the analysis plugin execution system entry point.
Uses a class-based registry for testability and DI support.
"""

import logging
from collections.abc import Callable
from typing import Any

from src.core.contracts.plugin_types import AnalysisExecutionContext

logger = logging.getLogger(__name__)


class DetectionRuntime:
    """Registry for detection context and plugin execution handlers."""

    def __init__(
        self,
        prime_ctx: Callable[..., AnalysisExecutionContext] | None = None,
        run_plugins: Callable[[AnalysisExecutionContext], dict[str, list[dict[str, Any]]]] | None = None,
    ) -> None:
        self._prime_context_handler = prime_ctx
        self._run_plugins_handler = run_plugins

    def prime_context(self, **kwargs: Any) -> AnalysisExecutionContext:
        logger.info("Initializing detection context with parameters: %s", list(kwargs.keys()))
        if self._prime_context_handler is not None:
            context = self._prime_context_handler(**kwargs)
            logger.info("Detection context initialized successfully.")
            return context
        raise RuntimeError("No prime_context_handler registered in DetectionRuntime")

    def run_plugins(self, context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
        logger.info("Running all registered detection plugins.")
        if self._run_plugins_handler is not None:
            results = self._run_plugins_handler(context)
            logger.info("Executed detection plugins. Returned results for %d plugins.", len(results))
            return results
        raise RuntimeError("No run_plugins_handler registered in DetectionRuntime")


_default_runtime: DetectionRuntime | None = None


def get_runtime() -> DetectionRuntime:
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = DetectionRuntime()
    return _default_runtime


def set_runtime(runtime: DetectionRuntime) -> None:
    global _default_runtime
    _default_runtime = runtime


def register_detection_handlers(
    prime_ctx: Callable[..., AnalysisExecutionContext],
    run_plugins: Callable[[AnalysisExecutionContext], dict[str, list[dict[str, Any]]]],
) -> None:
    get_runtime()._prime_context_handler = prime_ctx
    get_runtime()._run_plugins_handler = run_plugins


def prime_detection_context(**kwargs: Any) -> AnalysisExecutionContext:
    return get_runtime().prime_context(**kwargs)


def run_detection_plugins(context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
    return get_runtime().run_plugins(context)

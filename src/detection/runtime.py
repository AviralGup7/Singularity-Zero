"""Detection runtime facade delegating to the analysis layer.

Provides the analysis plugin execution system entry point.
"""

import logging
from collections.abc import Callable
from typing import Any

from src.core.contracts.plugin_types import AnalysisExecutionContext

logger = logging.getLogger(__name__)

_prime_context_handler: Callable[..., AnalysisExecutionContext] | None = None
_run_plugins_handler: Callable[[AnalysisExecutionContext], dict[str, list[dict[str, Any]]]] | None = None


def register_detection_handlers(
    prime_ctx: Callable[..., AnalysisExecutionContext],
    run_plugins: Callable[[AnalysisExecutionContext], dict[str, list[dict[str, Any]]]],
) -> None:
    global _prime_context_handler, _run_plugins_handler
    _prime_context_handler = prime_ctx
    _run_plugins_handler = run_plugins


def prime_detection_context(**kwargs: Any) -> AnalysisExecutionContext:
    """Initialize detection context (delegates to registered handler).

    Returns:
        Prepared AnalysisExecutionContext with URLs, responses, and config.
    """
    logger.info("Initializing detection context with parameters: %s", list(kwargs.keys()))
    if _prime_context_handler is not None:
        context = _prime_context_handler(**kwargs)
        logger.info("Detection context initialized successfully.")
        return context
    raise RuntimeError("No prime_context_handler registered in src.detection")


def run_detection_plugins(context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
    """Execute all registered detection/analysis plugins (delegates to registered handler).

    Args:
        context: Prepared analysis execution context.

    Returns:
        Dictionary mapping plugin names to their result lists.
    """
    logger.info("Running all registered detection plugins.")
    if _run_plugins_handler is not None:
        results = _run_plugins_handler(context)
        logger.info("Executed detection plugins. Returned results for %d plugins.", len(results))
        return results
    raise RuntimeError("No run_plugins_handler registered in src.detection")


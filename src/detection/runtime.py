"""Detection runtime facade delegating to the analysis layer.

Provides the analysis plugin execution system entry point.
"""

import logging
from typing import Any

from src.analysis.plugin_runtime import (
    prime_analysis_primitives,
    run_analysis_plugins,
)
from src.core.contracts.plugin_types import AnalysisExecutionContext

logger = logging.getLogger(__name__)


def prime_detection_context(**kwargs: Any) -> AnalysisExecutionContext:
    """Initialize detection context (delegates to analysis layer).

    Returns:
        Prepared AnalysisExecutionContext with URLs, responses, and config.
    """
    logger.info("Initializing detection context with parameters: %s", list(kwargs.keys()))
    context = prime_analysis_primitives(**kwargs)
    logger.info("Detection context initialized successfully.")
    return context


def run_detection_plugins(context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
    """Execute all registered detection/analysis plugins.

    Args:
        context: Prepared analysis execution context.

    Returns:
        Dictionary mapping plugin names to their result lists.
    """
    logger.info("Running all registered detection plugins.")
    results = run_analysis_plugins(context)
    logger.info("Executed detection plugins. Returned results for %d plugins.", len(results))
    return results

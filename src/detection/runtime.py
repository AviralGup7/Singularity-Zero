"""Detection runtime facade delegating to the analysis layer.

Provides the analysis plugin execution system entry point.
"""

from typing import Any

from src.analysis.plugin_runtime import (
    AnalysisExecutionContext,
    prime_analysis_primitives,
    run_analysis_plugins,
)


def prime_detection_context(**kwargs: Any) -> AnalysisExecutionContext:
    """Initialize detection context (delegates to analysis layer).

    Returns:
        Prepared AnalysisExecutionContext with URLs, responses, and config.
    """
    return prime_analysis_primitives(**kwargs)


def run_detection_plugins(context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
    """Execute all registered detection/analysis plugins.

    Args:
        context: Prepared analysis execution context.

    Returns:
        Dictionary mapping plugin names to their result lists.
    """
    return run_analysis_plugins(context)

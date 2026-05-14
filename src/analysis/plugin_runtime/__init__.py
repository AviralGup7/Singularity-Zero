"""Plugin runtime engine for executing analysis checks.

This package modularizes the plugin runtime into separate files
for better maintainability and AI-agent editability.
"""

from src.analysis.passive.runtime import ResponseCache
from src.analysis.plugin_runtime_models import (
    AnalysisExecutionContext,
    AnalyzerBinding,
    DetectionGraphContext,
)

from ._bindings import ANALYZER_BINDING, ANALYZER_BINDINGS
from ._runner import prime_analysis_primitives, run_analysis_plugins, run_registered_analyzer

__all__ = [
    "ANALYZER_BINDING",
    "ANALYZER_BINDINGS",
    "AnalysisExecutionContext",
    "AnalyzerBinding",
    "DetectionGraphContext",
    "ResponseCache",
    "prime_analysis_primitives",
    "run_registered_analyzer",
    "run_analysis_plugins",
]

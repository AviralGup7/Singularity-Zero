"""Analyzer bindings registry for the plugin runtime engine.

Re-exports from sub-modules for backward compatibility.
All implementation lives in:
- ``loader`` — LazyRunner and _lazy_import
- ``definitions`` — LAZY_BINDINGS data
- ``registry`` — _binding(), _register_bindings(), ANALYZER_BINDINGS
"""

from src.analysis.plugin_runtime.registry import (
    ANALYZER_BINDING,
    ANALYZER_BINDINGS,
    _binding,
    _get_bindings,
    _register_bindings,
)

__all__ = [
    "ANALYZER_BINDING",
    "ANALYZER_BINDINGS",
    "_binding",
    "_get_bindings",
    "_register_bindings",
]

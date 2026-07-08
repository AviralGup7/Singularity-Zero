"""Analyzer binding registry — registration, resolution, and public API.

Bug #4: ANALYZER_BINDINGS is now a lazy module-level attribute that re-evaluates
on each access. Previously it was computed once at import time via
``ANALYZER_BINDINGS = _get_bindings()``, meaning any plugins registered after
the initial import were invisible to the runtime.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from src.analysis.plugin_runtime.definitions import LAZY_BINDINGS
from src.analysis.plugin_runtime.loader import _lazy_import
from src.analysis.plugin_runtime_models import AnalyzerBinding
from src.core.plugins import list_plugins, register_plugin

ANALYZER_BINDING = "analyzer_binding"

_BINDINGS_REGISTERED = False


def _binding(
    input_kind: str,
    runner: Callable[..., list[dict[str, Any]]] | None = None,
    *,
    context_attr: str | None = None,
    limit_key: str | None = None,
    default_limit: int | None = None,
    extra_kwargs: dict[str, object] | None = None,
    phase: str = "discover",
    consumes: tuple[str, ...] = (),
    produces: tuple[str, ...] = (),
) -> AnalyzerBinding:
    """Create an analyzer binding for the plugin runtime engine."""
    return AnalyzerBinding(
        input_kind=input_kind,
        runner=runner,
        context_attr=context_attr,
        limit_key=limit_key,
        default_limit=default_limit,
        extra_kwargs=extra_kwargs,
        phase=phase,
        consumes=consumes,
        produces=produces,
    )


def _register_bindings() -> None:
    global _BINDINGS_REGISTERED
    if _BINDINGS_REGISTERED:
        return

    # Register lazy-loaded bindings from definitions
    for key, (module_path, attr_name, input_kind) in LAZY_BINDINGS.items():
        runner = _lazy_import(module_path, attr_name)
        binding = _binding(input_kind, runner)
        register_plugin(ANALYZER_BINDING, key)(binding)

    # Register inline bindings (pure stubs with no runner)
    inline_bindings = {
        "smart_payload_suggestions": _binding(
            "priority_urls_only",
            context_attr="priority_urls",
            limit_key="payload_suggestion_limit",
            default_limit=18,
            extra_kwargs={},
        ),
        "rate_limit_bypass_detector": _binding(
            "ranked_items_and_cache",
            limit_key="rate_limit_probe_limit",
            default_limit=10,
        ),
        "http_smuggling_detector": _binding(
            "ranked_items_and_cache",
            limit_key="smuggling_probe_limit",
            default_limit=8,
        ),
        "cognitive_flow_analysis": _binding(
            "urls_and_cache",
            limit_key="cognitive_flow_limit",
            default_limit=12,
        ),
        "behavior_analysis_layer": _binding("behavior_analysis"),
    }

    for key, binding in inline_bindings.items():
        register_plugin(ANALYZER_BINDING, key)(binding)

    _BINDINGS_REGISTERED = True


def _get_bindings() -> dict[str, AnalyzerBinding]:
    """Return the current bindings from the plugin registry.

    Bug #4: This is called on every access to ANALYZER_BINDINGS, not just
    once at import time. Plugins registered after the initial import are
    still visible.
    """
    _register_bindings()
    return {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}


# Bug #4: Use module-level __getattr__ so ANALYZER_BINDINGS is re-evaluated
# on every access. This means late-registered plugins appear automatically.
def __getattr__(name: str) -> dict[str, AnalyzerBinding]:
    if name == "ANALYZER_BINDINGS":
        return _get_bindings()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ANALYZER_BINDING",
    "_binding",
    "_get_bindings",
    "_register_bindings",
]

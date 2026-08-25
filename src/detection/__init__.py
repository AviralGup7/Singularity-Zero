from importlib import import_module
from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "detection",
    "version": "3.1.0",
    "description": (
        "Aggregates detection plugin specs and provides the runtime for "
        "active probing, WAF detection, AST analysis, browser runtime, "
        "and timing analysis."
    ),
    "layer": "detection",
    "submodules": (
        "api",
        "ast",
        "browser",
        "timing",
        "waf",
    ),
    "public_api": (
        "DETECTION_PLUGINS",
        "DETECTION_PLUGINS_BY_KEY",
        "DetectionPlugin",
        "DetectionFinding",
        "detection_plugin_options",
        "get_detection_plugin",
        "list_detection_plugins",
        "run_detection_plugin",
        "coverage",
        "handlers",
        "signals",
        "stateful",
    ),
    "depends_on": ("core", "recon"),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify detection subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``details`` / ``errors``.
    """
    try:
        from src.detection.registry import list_detection_plugins  # noqa: F401
        from src.detection.runtime import DetectionRuntime  # noqa: F401

        return {
            "status": "ok",
            "module": "detection",
            "version": "3.1.0",
            "details": {
                "detection_runtime": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "detection",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)


def __getattr__(name: str) -> Any:
    if name in {
        "DETECTION_PLUGINS",
        "DETECTION_PLUGINS_BY_KEY",
        "DetectionPlugin",
        "detection_plugin_options",
        "get_detection_plugin",
        "list_detection_plugins",
        "run_detection_plugin",
        "registry",
    }:
        module = import_module("src.detection.registry")
        if name == "registry":
            return module
        return getattr(module, name)
    if name in {"prime_detection_context", "run_detection_plugins", "runtime"}:
        module = import_module("src.detection.runtime")
        if name == "runtime":
            return module
        return getattr(module, name)
    if name in {"compose_signals", "signals"}:
        module = import_module("src.detection.signals")
        if name == "signals":
            return module
        return getattr(module, name)
    if name in {
        "DetectionFinding",
        "Evidence",
        "Exploitability",
        "Severity",
        "FindingOverrides",
        "clamp_confidence",
        "coerce_findings",
        "dicts_to_findings",
        "finding",
        "from_dict",
        "make_finding_id",
    }:
        module = import_module("src.detection.finding")
        if name == "finding":
            return module
        return getattr(module, name)
    if name in {
        "apply_referral",
        "coverage",
        "EXPLOIT_ENGINE_KEYS",
        "filter_actionable",
        "group_by_engine",
        "is_actionable",
        "recommend_engines",
        "referral_reasons",
        "referral_summary",
    }:
        module = import_module("src.detection.coverage")
        if name == "coverage":
            return module
        return getattr(module, name)
    if name in {
        "handlers",
        "get_handler",
        "list_handler_keys",
    }:
        module = import_module("src.detection.handlers")
        if name == "handlers":
            return module
        return getattr(module, name)
    if name in {"stateful"}:
        return import_module("src.detection.stateful")
    if name in {"ast"}:
        return import_module("src.detection.ast")
    if name in {"browser"}:
        return import_module("src.detection.browser")
    if name in {"waf"}:
        return import_module("src.detection.waf")
    if name in {"api"}:
        return import_module("src.detection.api")
    raise AttributeError(name)


__all__ = [
    "DETECTION_PLUGINS",
    "DETECTION_PLUGINS_BY_KEY",
    "DetectionPlugin",
    "DetectionFinding",
    "Evidence",
    "Exploitability",
    "Severity",
    "FindingOverrides",
    "EXPLOIT_ENGINE_KEYS",
    "apply_referral",
    "ast",
    "browser",
    "clamp_confidence",
    "compose_signals",
    "coerce_findings",
    "coverage",
    "dicts_to_findings",
    "filter_actionable",
    "from_dict",
    "get_detection_plugin",
    "get_handler",
    "group_by_engine",
    "handlers",
    "is_actionable",
    "list_detection_plugins",
    "list_handler_keys",
    "make_finding_id",
    "prime_detection_context",
    "recommend_engines",
    "referral_reasons",
    "referral_summary",
    "run_detection_plugin",
    "run_detection_plugins",
    "signals",
    "stateful",
    "waf",
    "api",
]

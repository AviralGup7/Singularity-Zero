"""Analysis package — active, passive, JSON, response, and behavior analyzers.

Lazy ``__getattr__`` facade re-exports ``ANALYSIS_PLUGIN_SPECS`` and
``analysis_check_options`` so callers never pay the import cost unless they
actually use those names.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "analysis",
    "version": "3.1.0",
    "description": (
        "Largest module: active/passive analyzers, plugin registration, "
        "intelligence scoring, response mutation, and automation helpers."
    ),
    "layer": "analysis",
    "submodules": (
        "active",
        "passive",
        "json",
        "response",
        "behavior",
        "automation",
        "bug_bounty",
        "checks",
        "helpers",
        "intelligence",
        "plugins",
        "plugin_runtime",
    ),
    "public_api": (
        "ANALYSIS_PLUGIN_SPECS",
        "ANALYSIS_PLUGIN_SPECS_BY_KEY",
        "analysis_check_options",
    ),
    "depends_on": ("core", "recon", "detection"),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify analysis subsystem health.

    Checks that the plugin registrar has bound analysis specs into the
    global plugin registry.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"error"``), ``module``,
        ``version``, and optional ``details`` / ``errors``.
    """
    try:
        from src.analysis.plugin_registration import (  # noqa: F401
            ANALYSIS_PLUGIN_REGISTRAR,
        )
        from src.core.plugins import list_plugins  # noqa: F401

        specs = ANALYSIS_PLUGIN_REGISTRAR.registry.list_plugins("detector_spec")
        return {
            "status": "ok",
            "module": "analysis",
            "version": "3.1.0",
            "details": {
                "registered_detector_specs": len(specs),
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "analysis",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Lazy facade (unchanged)
# ---------------------------------------------------------------------------


def __getattr__(name: str) -> Any:
    if name == "ANALYSIS_PLUGIN_SPECS":
        from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS

        return ANALYSIS_PLUGIN_SPECS
    if name == "ANALYSIS_PLUGIN_SPECS_BY_KEY":
        from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS_BY_KEY

        return ANALYSIS_PLUGIN_SPECS_BY_KEY
    if name == "analysis_check_options":
        from src.analysis.plugins import analysis_check_options

        return analysis_check_options
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ANALYSIS_PLUGIN_SPECS", "ANALYSIS_PLUGIN_SPECS_BY_KEY", "analysis_check_options"]

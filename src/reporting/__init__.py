from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "reporting",
    "version": "3.1.0",
    "description": (
        "Report generation, SARIF export, compliance attestation, "
        "remediation patches, and platform integrations (HackerOne, etc.)."
    ),
    "layer": "reporting",
    "submodules": ("platforms",),
    "public_api": ("generate_run_report",),
    "depends_on": ("core", "analysis", "intelligence", "decision", "execution"),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify reporting subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        import src.reporting.pages as _pages  # noqa: F401

        return {
            "status": "ok",
            "module": "reporting",
            "version": "3.1.0",
            "details": {"pages_module": "available"},
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "reporting",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)


# Lazy imports to avoid circular dependency
def __getattr__(name: str) -> Any:
    if name == "generate_run_report":
        from src.reporting.pages import generate_run_report as _gen

        return _gen
    import src.reporting.pipeline as _mod

    if hasattr(_mod, name):
        return getattr(_mod, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

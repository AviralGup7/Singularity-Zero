"""API security test runner with key workflow and result modules."""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "api_tests",
    "version": "3.1.0",
    "description": (
        "API security test runner with workflow registry, API key "
        "security checks, baseline-variant testing, and result formatting."
    ),
    "layer": "api_tests",
    "submodules": ("apitester",),
    "public_api": (
        "main",
        "run_api_key_checklist",
        "test_api_key_security",
        "advanced_api_key_test",
        "detailed_api_key_test",
        "test_api_baseline_vs_variant",
        "build_api_test_result",
        "list_workflows",
        "get_workflow",
    ),
    "depends_on": ("core",),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify api_tests subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        from src.api_tests.apitester.api_key_workflows import (  # noqa: F401
            list_workflows,
        )
        from src.api_tests.apitester.client import (  # noqa: F401
            display_secret,
            safe_request,
        )

        return {
            "status": "ok",
            "module": "api_tests",
            "version": "3.1.0",
            "details": {
                "workflow_registry": "available",
                "api_client": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "api_tests",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Public API re-exports (unchanged)
# ---------------------------------------------------------------------------

from .apitester.api_key_checklist import run_api_key_checklist
from .apitester.api_key_security import test_api_key_security
from .apitester.api_key_workflows import (
    WORKFLOW_SPECS,
    WORKFLOW_SPECS_BY_KEY,
    advanced_api_key_test,
    detailed_api_key_test,
    get_workflow,
    get_workflow_runner,
    list_workflows,
    subdomain_privilege_methods_test,
    write_flexible_chaining_test,
)
from .apitester.baseline_variant import test_api_baseline_vs_variant
from .apitester.cli import main
from .apitester.results import build_api_test_result

__all__ = [
    "advanced_api_key_test",
    "build_api_test_result",
    "detailed_api_key_test",
    "get_workflow",
    "get_workflow_runner",
    "list_workflows",
    "main",
    "run_api_key_checklist",
    "subdomain_privilege_methods_test",
    "test_api_baseline_vs_variant",
    "test_api_key_security",
    "WORKFLOW_SPECS",
    "WORKFLOW_SPECS_BY_KEY",
    "write_flexible_chaining_test",
]

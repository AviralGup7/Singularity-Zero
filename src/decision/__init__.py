"""Decision package re-exporting prioritization and attack selection functions.

Provides unified access to finding classification, decision annotation,
reportable filtering, and validation action selection.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "decision",
    "version": "3.1.0",
    "description": (
        "Scan prioritization and attack-selection logic: adaptive scan "
        "coordination, hunt-budget management, priority queues, and "
        "validation-action selection."
    ),
    "layer": "decision",
    "submodules": ("attack_selection", "prioritization"),
    "public_api": (
        "annotate_finding_decisions",
        "classify_finding",
        "DEFAULT_SELECTOR_CONFIG",
        "filter_reportable_findings",
        "select_validation_actions",
    ),
    "depends_on": ("core", "analysis"),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify decision subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        from src.decision.attack_selection import select_validation_actions  # noqa: F401
        from src.decision.prioritization import classify_finding  # noqa: F401

        return {
            "status": "ok",
            "module": "decision",
            "version": "3.1.0",
            "details": {
                "attack_selection": "available",
                "prioritization": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "decision",
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

from src.decision.attack_selection import DEFAULT_SELECTOR_CONFIG, select_validation_actions
from src.decision.prioritization import (
    annotate_finding_decisions,
    classify_finding,
    filter_reportable_findings,
)

__all__ = [
    "annotate_finding_decisions",
    "classify_finding",
    "DEFAULT_SELECTOR_CONFIG",
    "filter_reportable_findings",
    "select_validation_actions",
]

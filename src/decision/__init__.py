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
        "validation-action selection with immutable result models."
    ),
    "layer": "decision",
    "submodules": (
        "adaptive_scan",
        "attack_selection",
        "hunt_budget",
        "models",
        "prioritization",
        "priority_queue",
    ),
    "public_api": (
        "ActionSpec",
        "AdaptiveScanCoordinator",
        "AttackPlan",
        "AttackStep",
        "BudgetSnapshot",
        "CorrelationPriorityQueue",
        "DEFAULT_SELECTOR_CONFIG",
        "ExecutionRequest",
        "ExecutionResult",
        "Finding",
        "FindingDecision",
        "HuntBudget",
        "HuntBudgetEnforcer",
        "HuntMode",
        "ResourceLimits",
        "ScanPlan",
        "ScanResult",
        "ScanTarget",
        "ScopeToken",
        "StageRequest",
        "StageResult",
        "TargetSpec",
        "annotate_finding_decisions",
        "classify_finding",
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
        from src.decision.adaptive_scan import AdaptiveScanCoordinator  # noqa: F401
        from src.decision.attack_selection import select_validation_actions  # noqa: F401
        from src.decision.hunt_budget import HuntBudgetEnforcer  # noqa: F401
        from src.decision.models import (  # noqa: F401
            ExecutionRequest,
            ExecutionResult,
            FindingDecision,
            ScanPlan,
            ScanResult,
            StageResult,
        )
        from src.decision.prioritization import classify_finding  # noqa: F401
        from src.decision.priority_queue import CorrelationPriorityQueue  # noqa: F401

        return {
            "status": "ok",
            "module": "decision",
            "version": "3.1.0",
            "details": {
                "adaptive_scan": "available",
                "attack_selection": "available",
                "hunt_budget": "available",
                "models": "available",
                "prioritization": "available",
                "priority_queue": "available",
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
# Public API re-exports
# ---------------------------------------------------------------------------

from src.decision.adaptive_scan import AdaptiveScanCoordinator
from src.decision.attack_selection import (
    DEFAULT_SELECTOR_CONFIG,
    select_validation_actions,
    select_validation_attack_plans,
)
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer, HuntMode
from src.decision.models import (
    ActionSpec,
    AttackPlan,
    AttackStep,
    BudgetSnapshot,
    CandidateLease,
    ExecutionRequest,
    ExecutionResult,
    Finding,
    FindingDecision,
    ResourceLimits,
    ScanPlan,
    ScanResult,
    ScopeToken,
    StageRequest,
    StageResult,
    TargetSpec,
)
from src.decision.prioritization import (
    annotate_finding_decisions,
    classify_finding,
    filter_reportable_findings,
)
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget

__all__ = [
    "ActionSpec",
    "AdaptiveScanCoordinator",
    "AttackPlan",
    "AttackStep",
    "BudgetSnapshot",
    "CandidateLease",
    "CorrelationPriorityQueue",
    "DEFAULT_SELECTOR_CONFIG",
    "ExecutionRequest",
    "ExecutionResult",
    "Finding",
    "FindingDecision",
    "HuntBudget",
    "HuntBudgetEnforcer",
    "HuntMode",
    "ResourceLimits",
    "ScanPlan",
    "ScanResult",
    "ScanTarget",
    "ScopeToken",
    "StageRequest",
    "StageResult",
    "TargetSpec",
    "annotate_finding_decisions",
    "classify_finding",
    "filter_reportable_findings",
    "health_check",
    "select_validation_actions",
    "select_validation_attack_plans",
]

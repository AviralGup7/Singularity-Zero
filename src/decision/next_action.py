"""Single 'what next?' surface for the scheduler."""

from __future__ import annotations

from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer


def should_stop(enforcer: HuntBudgetEnforcer) -> bool:
    return enforcer.is_exhausted()


def bounded_enforcer(*, max_duration_seconds: float | None = None) -> HuntBudgetEnforcer:
    return HuntBudgetEnforcer(HuntBudget(max_duration_seconds=max_duration_seconds))


__all__ = ["bounded_enforcer", "should_stop"]

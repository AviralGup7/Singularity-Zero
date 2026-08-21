from __future__ import annotations

from src.decision.next_action import bounded_enforcer, should_stop


def test_unbounded_hunt_does_not_stop() -> None:
    enforcer = bounded_enforcer()
    assert should_stop(enforcer) is False


def test_zero_duration_budget_is_exhausted() -> None:
    enforcer = bounded_enforcer(max_duration_seconds=0.0)
    assert should_stop(enforcer) is True

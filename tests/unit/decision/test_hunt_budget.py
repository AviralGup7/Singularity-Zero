"""Unit tests for the hunter-centric HuntBudget / HuntMode extensions."""

from __future__ import annotations

from src.decision.hunt_budget import (
    DEFAULT_HIGH_VALUE_CATEGORIES,
    HuntBudget,
    HuntBudgetEnforcer,
    HuntMode,
)


class TestHuntMode:
    def test_default_disabled(self) -> None:
        mode = HuntMode()
        assert mode.enabled is False
        assert "idor" in mode.high_value_categories

    def test_from_config_honours_custom_categories(self) -> None:
        mode = HuntMode.from_config(
            {
                "hunt_mode": {
                    "enabled": True,
                    "high_value_categories": ["RACE_CONDITION", "BUSINESS_LOGIC"],
                }
            }
        )
        assert mode.enabled is True
        assert "race_condition" in mode.high_value_categories
        assert "business_logic" in mode.high_value_categories

    def test_is_high_value_substring_match(self) -> None:
        mode = HuntMode(high_value_categories=("idor", "ssrf"))
        assert mode.is_high_value("IDOR_FOUND")
        assert mode.is_high_value("ssrf in metadata")
        assert not mode.is_high_value("XSS")

    def test_is_low_hanging_fruit(self) -> None:
        mode = HuntMode(
            low_hanging_fruit_min_severity="medium",
            low_hanging_fruit_min_confidence=0.7,
            low_hanging_fruit_path_keywords=("admin", "auth"),
        )
        assert mode.is_low_hanging_fruit(
            category="idor", severity="high", confidence=0.8, url="/admin/users"
        )
        # Severity too low.
        assert not mode.is_low_hanging_fruit(
            category="idor", severity="low", confidence=0.8, url="/admin/users"
        )
        # Confidence too low.
        assert not mode.is_low_hanging_fruit(
            category="idor", severity="high", confidence=0.5, url="/admin/users"
        )
        # URL keyword missing.
        assert not mode.is_low_hanging_fruit(
            category="idor", severity="high", confidence=0.8, url="/about"
        )

    def test_default_high_value_categories_is_a_tuple(self) -> None:
        assert isinstance(DEFAULT_HIGH_VALUE_CATEGORIES, tuple)
        assert "idor" in DEFAULT_HIGH_VALUE_CATEGORIES


class TestHuntBudgetExtensions:
    def test_default_extended_fields(self) -> None:
        budget = HuntBudget()
        assert budget.stop_when_high_confidence_count is None
        assert budget.high_value_target_time_budget_pct == 0.4
        assert budget.high_confidence_threshold == 0.95
        assert budget.max_concurrent_probes == 5
        assert budget.countdown_visible is True

    def test_from_mapping_accepts_new_fields(self) -> None:
        budget = HuntBudget.from_mapping(
            {
                "max_duration_seconds": 7200,
                "stop_when_high_confidence_count": 4,
                "max_concurrent_probes": 8,
                "countdown_visible": False,
            }
        )
        assert budget.max_duration_seconds == 7200.0
        assert budget.stop_when_high_confidence_count == 4
        assert budget.max_concurrent_probes == 8
        assert budget.countdown_visible is False

    def test_to_dict_round_trip(self) -> None:
        budget = HuntBudget(
            max_duration_seconds=1800.0,
            stop_when_high_confidence_count=2,
            high_confidence_threshold=0.9,
        )
        again = HuntBudget.from_mapping(budget.to_dict())
        assert again.max_duration_seconds == 1800.0
        assert again.stop_when_high_confidence_count == 2
        assert again.high_confidence_threshold == 0.9


class TestHuntBudgetEnforcerExtensions:
    def test_high_confidence_counter(self) -> None:
        enforcer = HuntBudgetEnforcer(
            budget=HuntBudget(
                max_duration_seconds=10.0,
                high_confidence_threshold=0.9,
                stop_when_high_confidence_count=2,
            )
        )
        # Productive but not high-confidence.
        enforcer.record_finding(0.75)
        enforcer.record_finding(0.85)
        assert enforcer.high_confidence_findings == 0
        assert enforcer.productive_findings == 2
        assert not enforcer.is_exhausted()
        # High-confidence findings.
        enforcer.record_finding(0.95)
        enforcer.record_finding(0.99)
        assert enforcer.high_confidence_findings == 2
        assert enforcer.is_exhausted()
        enforcer.mark_terminated("test")
        assert enforcer.terminated_early is True

    def test_from_config_helper(self) -> None:
        enforcer = HuntBudgetEnforcer.from_config(
            {"hunt_budget": {"max_duration_seconds": 60, "stop_when_high_confidence_count": 3}},
            label="test",
        )
        assert enforcer.budget.max_duration_seconds == 60.0
        assert enforcer.budget.stop_when_high_confidence_count == 3
        assert enforcer.budget.label == "test"

    def test_exhausted_axes_falls_under_findings(self) -> None:
        enforcer = HuntBudgetEnforcer(budget=HuntBudget(stop_when_high_confidence_count=1))
        enforcer.record_finding(0.99)
        axes = enforcer.exhausted_axes()
        # FINDINGS axis is the one we report (and we don't leak the
        # high-confidence sub-axis into the public enum).
        from src.decision.hunt_budget import BudgetAxis

        assert BudgetAxis.FINDINGS in axes

    def test_reset_clears_high_confidence(self) -> None:
        enforcer = HuntBudgetEnforcer(budget=HuntBudget(stop_when_high_confidence_count=1))
        enforcer.record_finding(0.99)
        assert enforcer.is_exhausted()
        enforcer.reset()
        assert enforcer.high_confidence_findings == 0
        assert not enforcer.is_exhausted()

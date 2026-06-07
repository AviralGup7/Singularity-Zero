"""Tests for the validation config + bounded-confidence layer (R3, R8)."""

import unittest

from src.execution.validators.config import (
    CalibrationConfig,
    ReplaySafetyConfig,
    ScoringConfig,
    apply_bounded_confidence,
    load_validation_config,
    replay_safety_from_settings,
)
from src.execution.validators.config.scoring_config import (
    DEFAULT_SCORING_CONFIG,
    SignalConfirmationPolicy,
)
from src.execution.validators.validators.shared import bounded_confidence


class TestBoundedConfidenceHelper(unittest.TestCase):
    def test_confidence_is_capped(self) -> None:
        result = apply_bounded_confidence(
            config=ScoringConfig(base=0.5, cap=0.9, max_total_bonus=0.3),
            bonuses=[0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 1.0],
        )
        self.assertLessEqual(result.confidence, 0.9)
        self.assertEqual(result.bonus_total_capped, 0.3)

    def test_penalties_clamped(self) -> None:
        result = apply_bounded_confidence(
            config=ScoringConfig(base=0.5, cap=0.95, max_total_penalty=0.2),
            bonuses=[-1.0, -1.0],
        )
        self.assertEqual(result.penalty_total_capped, -0.2)

    def test_score_units_capped(self) -> None:
        result = apply_bounded_confidence(
            config=ScoringConfig(base=0.5, cap=0.99, score_weight=0.025),
            score=10_000,
        )
        self.assertLessEqual(result.score_contribution, 0.25 + 0.01)

    def test_validators_module_helper_matches(self) -> None:
        from src.analysis.helpers.scoring import apply_bounded_confidence as b2

        result = b2(base=0.5, score=3, signals=["callback"], bonuses=[0.1, 0.1])
        self.assertGreater(result, 0.5)
        self.assertLessEqual(result, 0.96)

    def test_validators_shared_bounded_confidence(self) -> None:
        result = bounded_confidence(
            base=0.5,
            cap=0.95,
            score=4,
            signal_weights=[2, 3],
            bonuses=[0.1, 0.1, 0.5, -0.1],
        )
        self.assertGreater(result, 0.5)
        self.assertLessEqual(result, 0.95)


class TestScoringConfigOverrides(unittest.TestCase):
    def test_merged_with_overrides(self) -> None:
        cfg = ScoringConfig(base=0.5, cap=0.9)
        merged = cfg.merged_with({"base": 0.55, "max_total_bonus": 0.2})
        self.assertEqual(merged.base, 0.55)
        self.assertEqual(merged.max_total_bonus, 0.2)
        self.assertEqual(merged.cap, 0.9)


class TestLoadValidationConfig(unittest.TestCase):
    def test_empty_settings_returns_defaults(self) -> None:
        cfg = load_validation_config(None)
        self.assertIn("ssrf", cfg.scoring)
        self.assertFalse(cfg.replay_safety.authorized_replay)

    def test_scoring_overrides_applied(self) -> None:
        cfg = load_validation_config(
            {
                "extensions": {
                    "blackbox_validation": {
                        "scoring": {"ssrf": {"base": 0.6, "cap": 0.98}},
                    }
                }
            }
        )
        ssrf = cfg.resolve_scoring("ssrf")
        self.assertEqual(ssrf.base, 0.6)
        self.assertEqual(ssrf.cap, 0.98)

    def test_replay_safety_overrides_applied(self) -> None:
        cfg = load_validation_config(
            {
                "extensions": {
                    "blackbox_validation": {
                        "token_replay_safety": {"authorized_replay": True},
                    }
                }
            }
        )
        self.assertTrue(cfg.replay_safety.authorized_replay)

    def test_scope_policy_defaults(self) -> None:
        cfg = load_validation_config({})
        self.assertTrue(cfg.scope_policy.block_active_when_unscoped)
        self.assertTrue(cfg.scope_policy.treat_unscoped_as_out_of_scope)


class TestReplaySafetyFactory(unittest.TestCase):
    def test_default_denies_replay(self) -> None:
        cfg = replay_safety_from_settings({})
        self.assertFalse(cfg.authorized_replay)

    def test_can_replay_respects_settings(self) -> None:
        cfg = ReplaySafetyConfig(authorized_replay=True)
        self.assertTrue(cfg.can_replay("authorization_header", 0))
        self.assertFalse(cfg.can_replay("response_body", 0))
        self.assertFalse(cfg.can_replay("authorization_header", 10))

    def test_severity_multiplier(self) -> None:
        cfg = ReplaySafetyConfig(authorized_replay=True)
        self.assertGreater(cfg.severity_for("authorization_header"), 1.0)
        self.assertEqual(cfg.severity_for("unknown"), 1.0)


class TestCalibrationConfig(unittest.TestCase):
    def test_scoring_for_applies_min_signals(self) -> None:
        cfg = CalibrationConfig(min_independent_signals=2)
        base = ScoringConfig(min_independent_signals=1)
        result = cfg.scoring_for("ssrf", base=base)
        self.assertEqual(result.min_independent_signals, 2)

    def test_scoring_for_preserves_higher_per_validator(self) -> None:
        cfg = CalibrationConfig(min_independent_signals=2)
        base = ScoringConfig(min_independent_signals=4)
        result = cfg.scoring_for("ssrf", base=base)
        self.assertEqual(result.min_independent_signals, 4)


class TestSignalConfirmationPolicy(unittest.TestCase):
    def test_confirms_when_required_group_satisfied(self) -> None:
        policy = SignalConfirmationPolicy(
            required_groups={
                "execution": ("math_evaluation", "template_error"),
            },
            min_groups_required=1,
        )
        self.assertTrue(policy.is_confirmed(["math_evaluation"]))
        self.assertFalse(policy.is_confirmed(["something_else"]))


class TestDefaultScoringConfigPresence(unittest.TestCase):
    def test_all_recommendation_validators_have_default(self) -> None:
        expected = {
            "ssrf",
            "redirect",
            "idor",
            "csrf",
            "file_upload",
            "xss",
            "ssti",
            "token_reuse",
            "cors",
            "race_condition",
            "jwt_weakness",
            "cache_poisoning",
            "graphql_abuse",
        }
        missing = expected - set(DEFAULT_SCORING_CONFIG)
        self.assertEqual(missing, set(), f"Missing scoring defaults: {missing}")


if __name__ == "__main__":
    unittest.main()

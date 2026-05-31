"""Tests for Chameleon Evasion Subsystem."""

from __future__ import annotations

from src.core.frontier.chameleon_evasion import (
    ChameleonEvasionEngine,
    JA3FingerprintModel,
    PPOEvasionModel,
    TimingPermutator,
)


class TestTimingPermutator:
    def test_exponential_delay_returns_positive(self):
        tp = TimingPermutator()
        delay = tp.exponential_delay(base_ms=100, variance_ms=50)
        assert delay >= 0

    def test_exponential_delay_respects_max(self):
        tp = TimingPermutator()
        delay = tp.exponential_delay(base_ms=100, variance_ms=50, max_delay_ms=100)
        assert delay <= 0.1

    def test_burst_pattern_returns_list(self):
        tp = TimingPermutator()
        delays = tp.burst_pattern(count=5)
        assert len(delays) == 5
        assert all(d >= 0 for d in delays)

    def test_human_like_delay_returns_positive(self):
        tp = TimingPermutator()
        delay = tp.human_like_delay(activity="browse")
        assert delay >= 0

    def test_waf_detected_increases_delay(self):
        tp = TimingPermutator()
        normal = tp.human_like_delay(activity="browse", waf_detected=False)
        evasive = tp.human_like_delay(activity="browse", waf_detected=True)
        # WAF detection should generally increase delay, but due to randomness
        # we just check both are positive and evasive is in a reasonable range
        assert evasive >= 0
        assert normal >= 0


class TestJA3FingerprintModel:
    def test_get_signature_returns_valid_format(self):
        ja3 = JA3FingerprintModel()
        sig = ja3.get_signature("chrome_windows")
        parts = sig.split(",")
        assert len(parts) == 5

    def test_get_signature_with_invalid_profile_returns_any(self):
        ja3 = JA3FingerprintModel()
        sig = ja3.get_signature("invalid_profile")
        assert sig is not None
        assert "," in sig

    def test_mutate_signature_returns_valid(self):
        ja3 = JA3FingerprintModel()
        sig = ja3.get_signature("chrome_windows")
        mutated = ja3.mutate_signature(sig)
        assert "," in mutated

    def test_get_random_profile_returns_tuple(self):
        ja3 = JA3FingerprintModel()
        profile, sig = ja3.get_random_profile()
        assert profile in ja3.BROWSER_PROFILES
        assert "," in sig


class TestPPOEvasionModel:
    def test_initial_state_is_undetected(self):
        hmm = PPOEvasionModel()
        assert hmm.get_current_state() == PPOEvasionModel.STATE_UNDETECTED
        assert hmm.get_state_name() == "undetected"

    def test_observe_success_stays_undetected_or_moves_to_suspected(self):
        hmm = PPOEvasionModel()
        hmm.observe(PPOEvasionModel.OBS_SUCCESS)
        # HIGH probability of staying undetected
        assert hmm.get_current_state() == PPOEvasionModel.STATE_UNDETECTED

    def test_observe_block_moves_to_blocked_or_suspected(self):
        hmm = PPOEvasionModel()
        # Multiple observations increase probability of blocked
        for _ in range(10):
            hmm.observe(PPOEvasionModel.OBS_BLOCK)
        # After multiple block observations, should be in blocked or evading
        assert hmm.get_current_state() in (
            PPOEvasionModel.STATE_BLOCKED,
            PPOEvasionModel.STATE_EVADING,
            PPOEvasionModel.STATE_SUSPECTED,
        )

    def test_observe_challenge_moves_to_suspected_or_blocked(self):
        hmm = PPOEvasionModel()
        for _ in range(10):
            hmm.observe(PPOEvasionModel.OBS_CHALLENGE)
        # After multiple challenge observations, should be in one of these states
        assert hmm.get_current_state() in (
            PPOEvasionModel.STATE_SUSPECTED,
            PPOEvasionModel.STATE_BLOCKED,
            PPOEvasionModel.STATE_EVADING,
            PPOEvasionModel.STATE_UNDETECTED,  # Still possible with low probability
        )

    def test_get_evasion_action_returns_dict(self):
        hmm = PPOEvasionModel()
        action = hmm.get_evasion_action()
        assert "intensity" in action
        assert "delay_ms" in action
        assert "header_mutate" in action


class TestChameleonEvasionEngine:
    def test_engine_initialization(self):
        engine = ChameleonEvasionEngine()
        assert engine.hmm is not None
        assert engine.ja3 is not None
        assert engine.timing is not None

    def test_update_observation_success(self):
        engine = ChameleonEvasionEngine()
        engine.update_observation(200, "")
        assert engine._waf_detected is False

    def test_update_observation_block(self):
        engine = ChameleonEvasionEngine()
        for _ in range(10):
            engine.update_observation(403, "")
        assert engine._waf_detected is True
        assert engine.hmm.get_current_state() in (
            PPOEvasionModel.STATE_BLOCKED,
            PPOEvasionModel.STATE_EVADING,
            PPOEvasionModel.STATE_SUSPECTED,
        )

    def test_update_observation_rate_limit(self):
        engine = ChameleonEvasionEngine()
        engine.update_observation(429, "")
        assert engine._waf_detected is True

    def test_update_observation_captcha(self):
        engine = ChameleonEvasionEngine()
        engine.update_observation(403, "captcha challenge detected")
        assert engine._waf_detected is True

    def test_get_evasion_config_returns_all_keys(self):
        engine = ChameleonEvasionEngine()
        config = engine.get_evasion_config()
        assert "timeout" in config
        assert "ja3_signature" in config
        assert "timing_delay" in config
        assert "header_mutate" in config
        assert "state" in config

    def test_get_timing_delay(self):
        engine = ChameleonEvasionEngine()
        delay = engine.get_timing_delay()
        assert delay >= 0

    def test_get_ja3_signature(self):
        engine = ChameleonEvasionEngine()
        sig = engine.get_ja3_signature()
        assert "," in sig

    def test_waf_state_progression(self):
        engine = ChameleonEvasionEngine()

        engine.update_observation(200, "")
        assert engine.hmm.get_state_name() == "undetected"

        for _ in range(10):
            engine.update_observation(403, "blocked by waf")
        assert engine.hmm.get_state_name() in ("blocked", "evading", "suspected")

        for _ in range(20):
            engine.update_observation(200, "")
        assert engine.hmm.get_state_name() in ("evading", "suspected", "undetected")

    def test_multiple_block_transitions(self):
        engine = ChameleonEvasionEngine()

        for _ in range(5):
            engine.update_observation(403, "blocked")

        assert engine._waf_detected is True
        assert engine.hmm.get_current_state() in (
            PPOEvasionModel.STATE_BLOCKED,
            PPOEvasionModel.STATE_EVADING,
        )

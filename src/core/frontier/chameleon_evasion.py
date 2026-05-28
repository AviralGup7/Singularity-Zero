"""
Chameleon Evasion Subsystem - Advanced WAF Evasion Engine

Implements:
- Hidden Markov Models for evasion state transitions
- JA3 TLS fingerprinting with browser profile simulation
- Dynamic timing permutation rules
"""

from __future__ import annotations

import math
import secrets
import threading
import time
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class TimingPermutator:
    """
    Generates human-like request timing patterns to evade behavioral WAF detection.
    Uses exponential distribution and burst patterns that mimic human browsing.
    """

    def __init__(self, seed: float | None = None):
        self._next_allowed: float = 0.0
        self._seed = seed or time.time()
        self._rng = secrets.SystemRandom()

    def exponential_delay(
        self,
        base_ms: float = 100.0,
        variance_ms: float = 50.0,
        max_delay_ms: float = 500.0,
    ) -> float:
        """
        Generate exponentially distributed delay (human-like).
        Mean = base_ms, StdDev = variance_ms.
        """
        u = self._rng.random()
        while u == 0:
            u = self._rng.random()
        delay = -math.log(u) * (variance_ms / 2) + base_ms
        return min(delay / 1000.0, max_delay_ms / 1000.0)

    def burst_pattern(self, count: int = 5, initial_delay_ms: float = 20.0) -> list[float]:
        """
        Generate burst timing (human scrolling through search results).
        Rapid first few, then slowing down.
        """
        delays = []
        for i in range(count):
            if i == 0:
                delay = initial_delay_ms / 1000.0
            else:
                delay = self.exponential_delay(
                    base_ms=initial_delay_ms * (1 - 0.1 * i),
                    variance_ms=30.0,
                )
            delays.append(delay)
        return delays

    def human_like_delay(
        self,
        activity: str = "browse",
        waf_detected: bool = False,
    ) -> float:
        """
        Select delay profile based on activity and detected WAF.
        """
        profiles = {
            "browse": (200.0, 100.0),
            "type": (150.0, 80.0),
            "think": (1000.0, 300.0),
            "scroll": (50.0, 30.0),
        }
        base, variance = profiles.get(activity, (200.0, 100.0))

        if waf_detected:
            base *= 1.5
            variance *= 2

        return max(0.0, self.exponential_delay(base_ms=base, variance_ms=variance))

    def wait_if_needed(self, min_interval_ms: float = 50.0) -> float:
        """Block until minimum interval has passed since last call."""
        now = time.time()
        wait_time = max(0.0, self._next_allowed - now)
        if wait_time > 0:
            time.sleep(wait_time)
        self._next_allowed = time.time() + (min_interval_ms / 1000.0)
        return wait_time


class JA3FingerprintModel:
    """
    Models TLS client fingerprints for evasion.
    Generates authentic JA3 signatures based on known browser profiles.
    """

    BROWSER_PROFILES: dict[str, dict[str, Any]] = {
        "chrome_windows": {
            "ssl_version": "771",
            "ciphers": "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
            "extensions": "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513",
            "ec": "29-23-24",
            "ec_point": "0",
        },
        "chrome_macos": {
            "ssl_version": "771",
            "ciphers": "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49201-49172-49202-156-157-47-53",
            "extensions": "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21",
            "ec": "29-23-24",
            "ec_point": "0",
        },
        "firefox_windows": {
            "ssl_version": "771",
            "ciphers": "4865-4866-4867-49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53",
            "extensions": "0-23-65281-10-11-35-16-5-13-18-51-45-43-27",
            "ec": "29-23-24",
            "ec_point": "0",
        },
        "safari_macos": {
            "ssl_version": "771",
            "ciphers": "4865-4866-4867-49195-49199-49196-49200-52393-52392-49161-49162-49171-49172-156-157-47-53",
            "extensions": "0-23-65281-10-11-35-16-5-13-18-51-45-43-27",
            "ec": "29-23-24",
            "ec_point": "0",
        },
        "edge_windows": {
            "ssl_version": "771",
            "ciphers": "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
            "extensions": "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513",
            "ec": "29-23-24",
            "ec_point": "0",
        },
    }

    def __init__(self) -> None:
        self._profile_keys = list(self.BROWSER_PROFILES.keys())
        self._rng = secrets.SystemRandom()

    def get_signature(self, profile: str | None = None) -> str:
        """Generate a JA3 signature for the given browser profile."""
        if profile and profile in self.BROWSER_PROFILES:
            p = self.BROWSER_PROFILES[profile]
        else:
            p = self.BROWSER_PROFILES[self._rng.choice(self._profile_keys)]

        return f"{p['ssl_version']},{p['ciphers']},{p['extensions']},{p['ec']},{p['ec_point']}"

    def mutate_signature(self, base_sig: str | None = None) -> str:
        """Slightly mutate a JA3 signature to evade static fingerprint matching."""
        sig = base_sig or self.get_signature()
        parts = sig.split(",")
        if len(parts) != 5:
            return sig

        ssl_ver, ciphers, extensions, ec, ec_point = parts

        cipher_list = ciphers.split("-")
        if len(cipher_list) > 1 and self._rng.random() > 0.7:
            i = self._rng.randint(0, len(cipher_list) - 2)
            cipher_list[i], cipher_list[i + 1] = cipher_list[i + 1], cipher_list[i]

        return f"{ssl_ver},{'-'.join(cipher_list)},{extensions},{ec},{ec_point}"

    def get_random_profile(self) -> tuple[str, str]:
        """Return a random (profile_name, ja3_signature) tuple."""
        profile = self._rng.choice(self._profile_keys)
        return profile, self.get_signature(profile)


class HMMEvasionModel:
    """
    Hidden Markov Model for WAF evasion state transitions.
    Models the hidden state of WAF detection and selects optimal evasion actions.
    """

    STATE_UNDETECTED = 0
    STATE_SUSPECTED = 1
    STATE_BLOCKED = 2
    STATE_EVADING = 3

    OBS_SUCCESS = 0
    OBS_CHALLENGE = 1
    OBS_BLOCK = 2
    OBS_RATE_LIMIT = 3

    def __init__(self) -> None:
        self._current_state = self.STATE_UNDETECTED
        self._state_history: list[int] = [self.STATE_UNDETECTED]
        self._rng = secrets.SystemRandom()

        self._transitions: dict[int, list[tuple[int, float]]] = {
            self.STATE_UNDETECTED: [
                (self.STATE_UNDETECTED, 0.85),
                (self.STATE_SUSPECTED, 0.12),
                (self.STATE_BLOCKED, 0.03),
            ],
            self.STATE_SUSPECTED: [
                (self.STATE_UNDETECTED, 0.30),
                (self.STATE_SUSPECTED, 0.40),
                (self.STATE_BLOCKED, 0.20),
                (self.STATE_EVADING, 0.10),
            ],
            self.STATE_BLOCKED: [
                (self.STATE_EVADING, 0.60),
                (self.STATE_BLOCKED, 0.30),
                (self.STATE_SUSPECTED, 0.10),
            ],
            self.STATE_EVADING: [
                (self.STATE_EVADING, 0.70),
                (self.STATE_SUSPECTED, 0.20),
                (self.STATE_UNDETECTED, 0.10),
            ],
        }

        self._emissions: dict[int, list[tuple[int, float]]] = {
            self.STATE_UNDETECTED: [
                (self.OBS_SUCCESS, 0.90),
                (self.OBS_CHALLENGE, 0.08),
                (self.OBS_BLOCK, 0.02),
                (self.OBS_RATE_LIMIT, 0.00),
            ],
            self.STATE_SUSPECTED: [
                (self.OBS_SUCCESS, 0.40),
                (self.OBS_CHALLENGE, 0.40),
                (self.OBS_BLOCK, 0.15),
                (self.OBS_RATE_LIMIT, 0.05),
            ],
            self.STATE_BLOCKED: [
                (self.OBS_SUCCESS, 0.10),
                (self.OBS_CHALLENGE, 0.10),
                (self.OBS_BLOCK, 0.60),
                (self.OBS_RATE_LIMIT, 0.20),
            ],
            self.STATE_EVADING: [
                (self.OBS_SUCCESS, 0.50),
                (self.OBS_CHALLENGE, 0.30),
                (self.OBS_BLOCK, 0.15),
                (self.OBS_RATE_LIMIT, 0.05),
            ],
        }

        # Initialize Cython/SIMD-equivalent optimized NumPy transition matrices
        try:
            import numpy as np
            self._np_transitions = np.array([
                [0.85, 0.12, 0.03, 0.00],  # row 0: STATE_UNDETECTED
                [0.30, 0.40, 0.20, 0.10],  # row 1: STATE_SUSPECTED
                [0.10, 0.00, 0.30, 0.60],  # row 2: STATE_BLOCKED
                [0.10, 0.20, 0.00, 0.70],  # row 3: STATE_EVADING
            ], dtype=np.float64)

            self._np_emissions = np.array([
                [0.90, 0.08, 0.02, 0.00],  # row 0: STATE_UNDETECTED
                [0.40, 0.40, 0.15, 0.05],  # row 1: STATE_SUSPECTED
                [0.10, 0.10, 0.60, 0.20],  # row 2: STATE_BLOCKED
                [0.50, 0.30, 0.15, 0.05],  # row 3: STATE_EVADING
            ], dtype=np.float64)
            self._use_np = True
        except ImportError:
            self._use_np = False

    def observe(self, observation: int) -> None:
        """Update model based on observed response."""
        self._state_history.append(self._current_state)

        # 1. Performance-Hardened Vectorized transition lookup fallback
        if getattr(self, "_use_np", False):
            try:
                import numpy as np
                probs = self._np_transitions[self._current_state] * self._np_emissions[:, observation]
                max_idx = int(np.argmax(probs))
                if probs[max_idx] > 0.0:
                    self._current_state = max_idx
                return
            except Exception:
                pass  # Fallback to pure-Python dictionary loop on any anomaly

        # 2. Pure-Python fallback loop
        max_prob = 0.0
        next_state = self._current_state

        for next_s, trans_prob in self._transitions.get(self._current_state, []):
            emit_prob = 0.0
            for obs, e_prob in self._emissions.get(next_s, []):
                if obs == observation:
                    emit_prob = e_prob
                    break
            prob = trans_prob * emit_prob
            if prob > max_prob:
                max_prob = prob
                next_state = next_s

        self._current_state = next_state

    def get_evasion_action(self) -> dict[str, Any]:
        """Return recommended evasion action based on current state."""
        actions = {
            self.STATE_UNDETECTED: {
                "intensity": "low",
                "delay_ms": 100,
                "header_mutate": False,
                "ja3_profile": None,
            },
            self.STATE_SUSPECTED: {
                "intensity": "medium",
                "delay_ms": 500,
                "header_mutate": True,
                "ja3_profile": "chrome_windows",
            },
            self.STATE_BLOCKED: {
                "intensity": "high",
                "delay_ms": 1500,
                "header_mutate": True,
                "ja3_profile": "firefox_windows",
            },
            self.STATE_EVADING: {
                "intensity": "maximum",
                "delay_ms": 3000,
                "header_mutate": True,
                "ja3_profile": "safari_macos",
            },
        }
        return actions.get(self._current_state, actions[self.STATE_UNDETECTED])

    def get_current_state(self) -> int:
        """Return current hidden state."""
        return self._current_state

    def get_state_name(self, state: int | None = None) -> str:
        """Return human-readable state name."""
        s = state if state is not None else self._current_state
        names = {
            self.STATE_UNDETECTED: "undetected",
            self.STATE_SUSPECTED: "suspected",
            self.STATE_BLOCKED: "blocked",
            self.STATE_EVADING: "evading",
        }
        return names.get(s, "unknown")


class ChameleonEvasionEngine:
    """
    Main evasion engine combining HMM state tracking, JA3 fingerprinting,
    and timing permutation for comprehensive WAF evasion.
    """

    def __init__(self) -> None:
        self.hmm = HMMEvasionModel()
        self.ja3 = JA3FingerprintModel()
        self.timing = TimingPermutator()
        self._waf_detected = False
        self.metrics: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def update_observation(
        self,
        response_status: int,
        body: str | None = None,
        session_id: str | None = None,
        target: str | None = None,
        detected_waf: str | None = None,
    ) -> None:
        """Update HMM based on HTTP response and record telemetry metrics."""
        if "captcha" in (body or "").lower() or "challenge" in (body or "").lower():
            self._waf_detected = True
            obs = HMMEvasionModel.OBS_CHALLENGE
        elif response_status == 200:
            obs = HMMEvasionModel.OBS_SUCCESS
        elif response_status in (403, 406, 418, 429, 503):
            self._waf_detected = True
            if response_status == 429:
                obs = HMMEvasionModel.OBS_RATE_LIMIT
            else:
                obs = HMMEvasionModel.OBS_BLOCK
        else:
            obs = HMMEvasionModel.OBS_SUCCESS

        self.hmm.observe(obs)

        # Telemetry / metrics tracking logic
        s_id = session_id or "default"
        t_id = target or "unknown"
        metric_key = f"{s_id}:{t_id}"

        with self._lock:
            if metric_key not in self.metrics:
                self.metrics[metric_key] = {
                    "session_id": s_id,
                    "target": t_id,
                    "total_requests": 0,
                    "successes": 0,
                    "blocks": 0,
                    "challenges": 0,
                    "evaded_requests": 0,
                    "detected_waf": None,
                    "current_state": "undetected",
                    "last_updated": 0.0,
                }

            entry = self.metrics[metric_key]
            entry["total_requests"] += 1
            entry["last_updated"] = time.time()
            entry["current_state"] = self.hmm.get_state_name()

            if detected_waf:
                entry["detected_waf"] = detected_waf

            if obs == HMMEvasionModel.OBS_SUCCESS:
                entry["successes"] += 1
                if self.hmm.get_current_state() == HMMEvasionModel.STATE_EVADING:
                    entry["evaded_requests"] += 1
            elif obs in (HMMEvasionModel.OBS_BLOCK, HMMEvasionModel.OBS_RATE_LIMIT):
                entry["blocks"] += 1
            elif obs == HMMEvasionModel.OBS_CHALLENGE:
                entry["challenges"] += 1

    def get_metrics(self) -> dict[str, Any]:
        """Thread-safe getter for evasion metrics."""
        with self._lock:
            import copy

            return copy.deepcopy(self.metrics)

    def reset_metrics(self) -> None:
        """Thread-safe reset for evasion metrics."""
        with self._lock:
            self.metrics.clear()

    def get_evasion_config(self) -> dict[str, Any]:
        """Get current evasion configuration based on HMM state."""
        action = self.hmm.get_evasion_action()

        return {
            "timeout": action["delay_ms"] / 1000.0 * 2 + 10.0,
            "ja3_signature": self.ja3.get_signature(action.get("ja3_profile"))
            if action.get("ja3_profile")
            else self.ja3.get_signature(),
            "timing_delay": self.timing.human_like_delay(
                activity="browse",
                waf_detected=self._waf_detected,
            ),
            "header_mutate": action.get("header_mutate", False),
            "state": self.hmm.get_state_name(),
        }

    def get_timing_delay(self) -> float:
        """Get current timing delay recommendation."""
        return self.timing.human_like_delay(
            activity="browse",
            waf_detected=self._waf_detected,
        )

    def get_ja3_signature(self) -> str:
        """Get current JA3 signature based on HMM state."""
        action = self.hmm.get_evasion_action()
        profile = action.get("ja3_profile")
        sig = self.ja3.get_signature(profile)
        return self.ja3.mutate_signature(sig)

"""Adaptive Proportional-Integral-Derivative (PID) Closed-Loop Flow Controller.

Autotunes request concurrency and inter-request delays based on real-time target
latency errors e(t), WAF error entropy, and socket pressure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class PIDTuning:
    """PID gain constants and operational limits."""

    kp: float = 0.5   # Proportional gain
    ki: float = 0.1   # Integral gain
    kd: float = 0.05  # Derivative gain
    target_latency_ms: float = 200.0
    min_concurrency: int = 1
    max_concurrency: int = 50
    min_delay_ms: float = 10.0
    max_delay_ms: float = 2000.0
    i_max: float = 500.0       # Anti-windup integral clamp bound
    iir_alpha: float = 0.2     # Derivative low-pass IIR filter coefficient (0.0 to 1.0)


class AdaptivePIDController:
    """Closed-loop controller dynamically tuning scan concurrency and throttle delays with anti-windup & IIR filtering."""

    def __init__(self, tuning: PIDTuning | None = None) -> None:
        self.tuning = tuning or PIDTuning()
        self._integral: float = 0.0
        self._last_error: float = 0.0
        self._filtered_derivative: float = 0.0
        self._last_time: float = time.time()
        self._current_concurrency: int = 10
        self._current_delay_ms: float = 50.0

    @property
    def current_concurrency(self) -> int:
        return self._current_concurrency

    @property
    def current_delay_ms(self) -> float:
        return self._current_delay_ms

    @property
    def integral(self) -> float:
        return self._integral

    @property
    def filtered_derivative(self) -> float:
        return self._filtered_derivative

    def observe(self, observed_latency_ms: float, error_occurred: bool = False) -> tuple[int, float]:
        """Feed latest observation into the PID loop and compute adjusted concurrency & delay."""
        now = time.time()
        dt = max(0.001, now - self._last_time)
        self._last_time = now

        # Add penalty if network/WAF error occurred
        effective_latency = observed_latency_ms * (2.5 if error_occurred else 1.0)
        error = self.tuning.target_latency_ms - effective_latency

        # Saturation freeze (anti-windup): freeze integral accumulation if saturated
        is_max_saturated = (self._current_concurrency >= self.tuning.max_concurrency and error > 0)
        is_min_saturated = (self._current_concurrency <= self.tuning.min_concurrency and error < 0)

        if not (is_max_saturated or is_min_saturated):
            self._integral += error * dt
            # Clamp integral accumulator to [-Imax, Imax]
            self._integral = max(-self.tuning.i_max, min(self.tuning.i_max, self._integral))

        # Derivative with low-pass IIR filter
        raw_derivative = (error - self._last_error) / dt
        alpha = self.tuning.iir_alpha
        self._filtered_derivative = (alpha * raw_derivative) + ((1.0 - alpha) * self._filtered_derivative)
        self._last_error = error

        control_signal = (
            (self.tuning.kp * error)
            + (self.tuning.ki * self._integral)
            + (self.tuning.kd * self._filtered_derivative)
        )

        # Scale concurrency: positive control signal -> target fast, increase concurrency
        concurrency_delta = int(control_signal / 50.0)
        self._current_concurrency = max(
            self.tuning.min_concurrency,
            min(self.tuning.max_concurrency, self._current_concurrency + concurrency_delta),
        )

        # Scale inter-request delay inversely to control signal
        delay_delta = -control_signal * 0.2
        self._current_delay_ms = max(
            self.tuning.min_delay_ms,
            min(self.tuning.max_delay_ms, self._current_delay_ms + delay_delta),
        )

        return self._current_concurrency, self._current_delay_ms


__all__ = [
    "AdaptivePIDController",
    "PIDTuning",
]

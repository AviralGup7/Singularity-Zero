"""Adaptive Proportional-Integral-Derivative (PID) Closed-Loop Flow Controller.

Autotunes request concurrency and inter-request delays based on real-time target
latency errors e(t), WAF error entropy, and socket pressure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class PIDTuning:
    """PID gain constants and operational limits."""

    kp: float = 0.5  # Proportional gain
    ki: float = 0.1  # Integral gain
    kd: float = 0.05  # Derivative gain
    target_latency_ms: float = 200.0
    min_concurrency: int = 1
    max_concurrency: int = 50
    min_delay_ms: float = 10.0
    max_delay_ms: float = 2000.0
    i_max: float = 500.0  # Anti-windup integral clamp bound
    iir_alpha: float = 0.2  # Derivative low-pass IIR filter coefficient (0.0 to 1.0)


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

    def observe(
        self, observed_latency_ms: float, error_occurred: bool = False
    ) -> tuple[int, float]:
        """Feed latest observation into the PID loop and compute adjusted concurrency & delay."""
        now = time.time()
        dt = max(0.001, now - self._last_time)
        self._last_time = now

        # Add penalty if network/WAF error occurred
        effective_latency = observed_latency_ms * (2.5 if error_occurred else 1.0)
        error = self.tuning.target_latency_ms - effective_latency

        # Saturation freeze (anti-windup): freeze integral accumulation if saturated
        is_max_saturated = self._current_concurrency >= self.tuning.max_concurrency and error > 0
        is_min_saturated = self._current_concurrency <= self.tuning.min_concurrency and error < 0

        if not (is_max_saturated or is_min_saturated):
            self._integral += error * dt
            # Clamp integral accumulator to [-Imax, Imax]
            self._integral = max(-self.tuning.i_max, min(self.tuning.i_max, self._integral))

        # Derivative with low-pass IIR filter
        raw_derivative = (error - self._last_error) / dt
        alpha = self.tuning.iir_alpha
        self._filtered_derivative = (alpha * raw_derivative) + (
            (1.0 - alpha) * self._filtered_derivative
        )
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


class PIDRateLimiter:
    """Closed-loop PID controller regulating request pacing based on response latency."""

    def __init__(
        self,
        target_latency_seconds: float = 0.200,
        kp: float = 0.5,
        ki: float = 0.1,
        kd: float = 0.05,
        min_delay_seconds: float = 0.0,
        max_delay_seconds: float = 5.0,
        integral_limit: float | None = None,
    ):
        self.target_latency = target_latency_seconds
        self.kp = kp
        self.ki = ki
        self.kd = kd
        self.min_delay = min_delay_seconds
        self.max_delay = max_delay_seconds
        if integral_limit is None:
            integral_limit = max_delay_seconds / max(ki, 1e-9)
        self.integral_limit = abs(integral_limit)

        self.current_delay = min_delay_seconds
        self.integral = 0.0
        self.last_error = 0.0
        self.last_time = time.monotonic()

    def update(self, observed_latency_seconds: float, is_blocked: bool = False) -> float:
        """Update the PID controller state and return the new delay pacing."""
        now = time.monotonic()
        dt = now - self.last_time
        if dt <= 0.0:
            dt = 0.001

        if is_blocked:
            self.current_delay = min(self.max_delay, self.current_delay + 1.5)
            self.integral = 0.0
            self.last_error = 0.0
            self.last_time = now
            return self.current_delay

        error = observed_latency_seconds - self.target_latency

        p_term = self.kp * error
        self.integral += error * dt
        self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral))
        i_term = self.ki * self.integral
        derivative = (error - self.last_error) / dt
        d_term = self.kd * derivative

        output = p_term + i_term + d_term
        unclamped_delay = self.current_delay + output
        self.current_delay = max(self.min_delay, min(self.max_delay, unclamped_delay))
        if self.ki > 0 and unclamped_delay != self.current_delay:
            saturation_excess = (unclamped_delay - self.current_delay) / self.ki
            self.integral -= saturation_excess
            self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral))

        self.last_error = error
        self.last_time = now

        return round(self.current_delay, 3)


__all__ = [
    "AdaptivePIDController",
    "PIDRateLimiter",
    "PIDTuning",
]

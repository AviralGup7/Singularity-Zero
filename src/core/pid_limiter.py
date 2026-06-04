"""Proactive Concurrency Control utilizing a PID Rate Limiter."""

from __future__ import annotations

import time


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
        """Update the PID controller state and return the new delay pacing.

        Args:
            observed_latency_seconds: The round-trip time of the last request.
            is_blocked: True if the target returned a 429/503 blocking indicator.

        Returns:
            The calculated delay pacing in seconds.
        """
        now = time.monotonic()
        dt = now - self.last_time
        if dt <= 0.0:
            dt = 0.001

        if is_blocked:
            # Immediate severe penalty on block
            self.current_delay = min(self.max_delay, self.current_delay + 1.5)
            self.integral = 0.0
            self.last_error = 0.0
            self.last_time = now
            return self.current_delay

        # Calculate error (observed - target)
        error = observed_latency_seconds - self.target_latency

        # P, I, D Terms
        p_term = self.kp * error
        self.integral += error * dt
        # Anti-windup: clamp integral to prevent unbounded accumulation when output saturates
        self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral))
        i_term = self.ki * self.integral
        derivative = (error - self.last_error) / dt
        d_term = self.kd * derivative

        # Control output adjusts the pacing delay
        output = p_term + i_term + d_term
        unclamped_delay = self.current_delay + output
        self.current_delay = max(self.min_delay, min(self.max_delay, unclamped_delay))
        # Back-calculation: if we saturated, subtract the excess from integral
        if self.ki > 0 and unclamped_delay != self.current_delay:
            saturation_excess = (unclamped_delay - self.current_delay) / self.ki
            self.integral -= saturation_excess
            self.integral = max(-self.integral_limit, min(self.integral_limit, self.integral))

        # Save states
        self.last_error = error
        self.last_time = now

        return round(self.current_delay, 3)

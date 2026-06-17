"""Rate-limited request scheduler with adaptive backoff.

Moved from ``src.analysis.passive.runtime`` to ``src.core`` so that
execution-layer modules can import it without violating the
execution -> analysis forbidden-import contract.
"""

from __future__ import annotations

import threading
import time
from typing import Any


class RequestScheduler:
    def __init__(
        self,
        rate_per_second: float,
        capacity: float,
        *,
        adaptive_mode: bool = False,
        max_rate_per_second: float | None = None,
        max_capacity: float | None = None,
        min_rate_per_second: float | None = None,
        latency_threshold_seconds: float = 1.5,
        increase_step: float = 0.5,
        success_window: int = 4,
        error_backoff_factor: float = 0.5,
        latency_backoff_factor: float = 0.75,
    ) -> None:
        self.rate_per_second = max(rate_per_second, 0.01)
        self.capacity = max(capacity, 1.0)
        self.adaptive_mode = adaptive_mode
        self.max_rate_per_second = max(
            self.rate_per_second,
            max_rate_per_second
            if max_rate_per_second is not None
            else max(self.rate_per_second * 3.0, self.rate_per_second + 4.0),
        )
        self.max_capacity = max(
            self.capacity,
            max_capacity
            if max_capacity is not None
            else max(self.capacity * 2.0, self.capacity + 2.0),
        )
        self.min_rate_per_second = max(
            0.1,
            min_rate_per_second
            if min_rate_per_second is not None
            else max(self.rate_per_second * 0.25, 0.25),
        )
        self.latency_threshold_seconds = max(latency_threshold_seconds, 0.1)
        self.increase_step = max(increase_step, 0.1)
        self.success_window = max(success_window, 1)
        self.error_backoff_factor = min(max(error_backoff_factor, 0.1), 0.95)
        self.latency_backoff_factor = min(max(latency_backoff_factor, 0.1), 0.99)
        self.current_rate_per_second = self.rate_per_second
        self.current_capacity = self.capacity
        self.tokens = self.current_capacity
        self.last_refill = time.monotonic()
        self._healthy_streak = 0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        loop = None
        try:
            import asyncio

            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(
                    self.current_capacity, self.tokens + elapsed * self.current_rate_per_second
                )
                self.last_refill = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                deficit = 1.0 - self.tokens
                required_sleep = deficit / self.current_rate_per_second

            sleep_time = max(0.01, required_sleep)
            if loop is not None and loop.is_running():
                import threading as _threading

                loop_thread = getattr(loop, "_thread", None)
                if loop_thread is not None and _threading.current_thread() != loop_thread:
                    try:
                        future = asyncio.run_coroutine_threadsafe(asyncio.sleep(sleep_time), loop)
                        future.result()
                        continue
                    except (TimeoutError, RuntimeError, OSError):
                        pass
            time.sleep(sleep_time)

    async def acquire_async(self) -> None:
        """Non-blocking async acquire that uses asyncio.sleep."""
        import asyncio

        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(
                    self.current_capacity, self.tokens + elapsed * self.current_rate_per_second
                )
                self.last_refill = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                deficit = 1.0 - self.tokens
                required_sleep = deficit / self.current_rate_per_second
            await asyncio.sleep(max(0.01, required_sleep))

    def observe(
        self,
        successful: bool,
        latency_seconds: float,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        if not self.adaptive_mode:
            return
        with self._lock:
            if retry_after_seconds is not None and retry_after_seconds > 0:
                backoff_factor = max(0.1, 1.0 / (1.0 + retry_after_seconds))
                self.current_rate_per_second = max(
                    self.min_rate_per_second, self.current_rate_per_second * backoff_factor
                )
                self.current_capacity = max(
                    1.0, min(self.max_capacity, self.current_capacity * backoff_factor)
                )
                self.tokens = min(self.tokens, self.current_capacity)
                self._healthy_streak = 0
                return

            if successful and latency_seconds <= self.latency_threshold_seconds:
                self._healthy_streak += 1
                if self._healthy_streak < self.success_window:
                    return
                self._healthy_streak = 0
                self.current_rate_per_second = min(
                    self.max_rate_per_second, self.current_rate_per_second + self.increase_step
                )
                self.current_capacity = min(
                    self.max_capacity, self.current_capacity + max(self.increase_step / 2.0, 0.25)
                )
                self.tokens = min(self.tokens, self.current_capacity)
                return

            self._healthy_streak = 0
            if status_code == 429:
                factor = self.error_backoff_factor * 0.5
            elif not successful:
                factor = self.error_backoff_factor
            else:
                factor = self.latency_backoff_factor
            self.current_rate_per_second = max(
                self.min_rate_per_second, self.current_rate_per_second * factor
            )
            self.current_capacity = max(1.0, min(self.max_capacity, self.current_capacity * factor))
            self.tokens = min(self.tokens, self.current_capacity)

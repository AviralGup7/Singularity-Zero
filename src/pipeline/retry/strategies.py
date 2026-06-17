"""Retry strategies: backoff, jitter, adaptive heuristic, and async sleep helpers."""

from __future__ import annotations

import asyncio
import re
import secrets as random
import time
from dataclasses import dataclass, field
from typing import Any, TypeVar

from src.core.logging.trace_logging import get_pipeline_logger

_SYSTEM_RANDOM = random.SystemRandom()

T = TypeVar("T")

_RETRY_AFTER_RE = re.compile(r"[Rr]etry-[Aa]fter:\s*(\d+)", re.IGNORECASE)
_HTTP_429_RE = re.compile(r"429|rate.?limit|too.?many.?requests", re.IGNORECASE)


def parse_retry_after(stderr_text: str) -> int | None:
    """Extract Retry-After seconds from tool stderr/stdout text. Returns None if absent."""
    if not stderr_text:
        return None
    m = _RETRY_AFTER_RE.search(stderr_text)
    if m:
        try:
            return max(1, int(m.group(1)))
        except (TypeError, ValueError) as exc:
            logger.warning("Operation failed in strategies.py: %s", exc, exc_info=True)  # noqa: BLE001
    return None


def detect_rate_limit(stderr_text: str) -> bool:
    """Return True if stderr indicates a rate-limit / 429 response."""
    if not stderr_text:
        return False
    return bool(_HTTP_429_RE.search(stderr_text))


class RetryAfterAwareMixin:
    """Mixin to override backoff when a tool signals Retry-After."""

    @staticmethod
    def delay_for_attempt_with_retry_after(
        base_policy: Any,
        attempt_number: int,
        stderr_text: str = "",
    ) -> float:
        retry_after = parse_retry_after(stderr_text)
        if retry_after is not None:
            return float(retry_after)
        return float(base_policy.delay_for_attempt(attempt_number))


logger = get_pipeline_logger(__name__)


@dataclass
class AdaptiveBackoffHeuristic:
    """Vegas-style feedback controller for the exponential backoff multiplier."""

    initial_multiplier: float = 2.0
    min_multiplier: float = 1.0
    max_multiplier: float = 4.0
    window_size: int = 8
    adjustment_interval: int = 4
    success_threshold: float = 0.5
    step_up_factor: float = 1.5
    step_down_factor: float = 0.75
    dampening: float = 0.3

    _window: list[bool] = field(default_factory=list, repr=False)
    _current_multiplier: float = field(init=False)
    _observation_count: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        self._current_multiplier = max(self.min_multiplier, self.initial_multiplier)

    @property
    def current_multiplier(self) -> float:
        return self._current_multiplier

    def observe(self, outcome: bool) -> None:
        self._window.append(outcome)
        self._observation_count += 1
        if len(self._window) > self.window_size:
            self._window = self._window[-self.window_size :]
        if self._observation_count % self.adjustment_interval == 0:
            self._adjust()

    def _adjust(self) -> None:
        if not self._window:
            return
        success_rate = sum(1 for w in self._window if w) / len(self._window)
        if success_rate < self.success_threshold:
            candidate = self._current_multiplier * self.step_up_factor
        else:
            candidate = self._current_multiplier * self.step_down_factor
        raw = self._current_multiplier + (candidate - self._current_multiplier) * self.dampening
        self._current_multiplier = max(self.min_multiplier, min(self.max_multiplier, raw))

    def reset(self) -> None:
        self._window.clear()
        self._observation_count = 0
        self._current_multiplier = max(self.min_multiplier, self.initial_multiplier)

    def copy(self) -> AdaptiveBackoffHeuristic:
        return AdaptiveBackoffHeuristic(
            initial_multiplier=self.initial_multiplier,
            min_multiplier=self.min_multiplier,
            max_multiplier=self.max_multiplier,
            window_size=self.window_size,
            adjustment_interval=self.adjustment_interval,
            success_threshold=self.success_threshold,
            step_up_factor=self.step_up_factor,
            step_down_factor=self.step_down_factor,
            dampening=self.dampening,
        )


def is_retryable(exc: BaseException, policy: Any) -> bool:
    """Determine whether an exception should trigger a retry."""
    from src.pipeline.retry.classifier import classify_error

    classification = classify_error(exc)
    if classification == "permanent":
        return False
    if classification == "transient":
        if isinstance(exc, TimeoutError) and not policy.retry_on_timeout:
            return False
        return True
    if classification == "unknown":
        return bool(policy.retry_on_error)
    return False


def retry_ready(policy: Any, attempt: int) -> bool:
    """Return True when another retry attempt is still allowed."""
    return bool(attempt < policy.max_attempts)


def sleep_before_retry(policy: Any, attempt: int) -> float:
    delay = float(policy.delay_for_attempt(attempt + 1))
    if delay > 0:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                logger.warning(
                    "sleep_before_retry called from async context without being awaited; "
                    "use sleep_before_retry_async instead"
                )
        except RuntimeError:
            pass
        time.sleep(delay)
    return delay


async def sleep_before_retry_async(
    policy: Any,
    attempt: int,
    shutdown_event: asyncio.Event | None = None,
) -> float:
    """Async drop-in replacement for sleep_before_retry."""
    delay = float(policy.delay_for_attempt(attempt + 1))
    if delay <= 0:
        return 0.0
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        raise
    if shutdown_event is not None and shutdown_event.is_set():
        raise asyncio.CancelledError("Shutdown signalled during retry backoff")
    return delay


async def cancellable_sleep(
    seconds: float,
    shutdown_event: asyncio.Event | None = None,
    *,
    check_interval: float = 0.1,
) -> None:
    """Sleep for *seconds*, short-circuiting on cancel or shutdown."""
    if seconds <= 0:
        return
    remaining = seconds
    while remaining > 0:
        current_task = asyncio.current_task()
        if current_task is not None and current_task.cancelled():
            raise asyncio.CancelledError()
        if shutdown_event is not None and shutdown_event.is_set():
            raise asyncio.CancelledError("Shutdown signalled")
        chunk = min(remaining, check_interval)
        try:
            await asyncio.sleep(chunk)
        except asyncio.CancelledError:
            raise
        remaining -= chunk

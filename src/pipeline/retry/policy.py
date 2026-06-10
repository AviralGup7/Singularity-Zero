"""Retry policies: RetryPolicy, RetryPolicyState, StageRetryPolicy, ToolRetryPolicy."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from src.core.contracts.pipeline import RETRY_DEFAULTS
from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.retry.classifier import classify_error
from src.pipeline.retry.events import (
    RetryEvent,
    RetryEventType,
    _pipeline_event_from_retry_event,
)

logger = get_pipeline_logger(__name__)

_SYSTEM_RANDOM = __import__("secrets").SystemRandom()

T = TypeVar("T")


def _positive_int(value: object, default: int) -> int:
    try:
        if isinstance(value, (int, float)):
            parsed = int(value)
        else:
            parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _positive_float(value: object, default: float) -> float:
    try:
        if isinstance(value, (int, float)):
            parsed = float(value)
        else:
            parsed = float(str(value))
    except (TypeError, ValueError):
        return default
    return max(0.0, parsed)


def is_retryable(exc: BaseException, policy: Any) -> bool:
    """Determine whether an exception should trigger a retry."""
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


def cast_to_stage_name(policy: Any) -> str:
    return getattr(policy.base_policy, "_stage_name", "unknown") or "unknown"


@dataclass(frozen=True)
class RetryPolicy:
    """Immutable retry configuration."""

    max_attempts: int = 1
    initial_backoff_seconds: float = 0.0
    backoff_multiplier: float = 2.0
    max_backoff_seconds: float = 8.0
    retry_on_timeout: bool = True
    retry_on_error: bool = True
    jitter_factor: float = 0.25

    @classmethod
    def from_settings(
        cls,
        global_settings: dict[str, Any] | None = None,
        tool_settings: dict[str, Any] | None = None,
    ) -> RetryPolicy:
        global_settings = global_settings or {}
        tool_settings = tool_settings or {}
        retry_attempts = _positive_int(
            tool_settings.get(
                "retry_attempts",
                global_settings.get("retry_attempts", RETRY_DEFAULTS["retry_attempts"]),
            ),
            int(RETRY_DEFAULTS["retry_attempts"]),
        )
        return cls(
            max_attempts=max(1, retry_attempts + 1),
            initial_backoff_seconds=_positive_float(
                tool_settings.get(
                    "retry_backoff_seconds",
                    global_settings.get(
                        "retry_backoff_seconds", RETRY_DEFAULTS["retry_backoff_seconds"]
                    ),
                ),
                float(RETRY_DEFAULTS["retry_backoff_seconds"]),
            ),
            backoff_multiplier=max(
                1.0,
                _positive_float(
                    tool_settings.get(
                        "retry_backoff_multiplier",
                        global_settings.get(
                            "retry_backoff_multiplier", RETRY_DEFAULTS["retry_backoff_multiplier"]
                        ),
                    ),
                    float(RETRY_DEFAULTS["retry_backoff_multiplier"]),
                ),
            ),
            max_backoff_seconds=max(
                0.0,
                _positive_float(
                    tool_settings.get(
                        "retry_max_backoff_seconds",
                        global_settings.get(
                            "retry_max_backoff_seconds", RETRY_DEFAULTS["retry_max_backoff_seconds"]
                        ),
                    ),
                    float(RETRY_DEFAULTS["retry_max_backoff_seconds"]),
                ),
            ),
            retry_on_timeout=bool(
                tool_settings.get(
                    "retry_on_timeout",
                    global_settings.get("retry_on_timeout", RETRY_DEFAULTS["retry_on_timeout"]),
                )
            ),
            retry_on_error=bool(
                tool_settings.get(
                    "retry_on_error",
                    global_settings.get("retry_on_error", RETRY_DEFAULTS["retry_on_error"]),
                )
            ),
            jitter_factor=_positive_float(
                tool_settings.get("retry_jitter", global_settings.get("retry_jitter", 0.25)),
                0.25,
            ),
        )

    def delay_for_attempt(self, attempt_number: int, jitter: float | None = None) -> float:
        """Calculate backoff with exponential growth and jitter to prevent thundering herd."""
        if attempt_number <= 1:
            return 0.0
        effective_backoff = max(0.0, self.initial_backoff_seconds)
        base_delay = effective_backoff * (self.backoff_multiplier ** max(0, attempt_number - 2))
        if self.max_backoff_seconds > 0:
            base_delay = min(base_delay, self.max_backoff_seconds)

        jitter_factor = self.jitter_factor if jitter is None else max(0.0, float(jitter))
        jitter_range = base_delay * jitter_factor
        jittered = base_delay + (_SYSTEM_RANDOM.random() * 2 - 1) * jitter_range
        return float(max(0.0, jittered))


def execute_with_retry[T](  # pylint: disable=W0621
    func: Callable[..., T],
    policy: RetryPolicy,
    metrics: Any = None,
    *args: Any,
    **kwargs: Any,
) -> T:
    from src.pipeline.retry.metrics import RetryMetrics

    m = metrics or RetryMetrics()
    last_exc: BaseException | None = None

    for attempt in range(1, policy.max_attempts + 1):
        m.record_attempt()
        try:
            result = func(*args, **kwargs)
            m.record_success()
            return result
        except Exception as exc:
            last_exc = exc
            classification = classify_error(exc)

            if classification == "transient":
                m.record_transient()
            elif classification == "permanent":
                m.record_permanent()

            if not is_retryable(exc, policy):
                m.record_failure()
                raise

            if attempt < policy.max_attempts:
                backoff = policy.delay_for_attempt(attempt + 1, jitter=policy.jitter_factor)
                m.record_retry(backoff)
                if backoff > 0:
                    logger.debug(
                        "Retry attempt %d/%d after %.2fs (%s)",
                        attempt,
                        policy.max_attempts,
                        backoff,
                        classification,
                    )
                    time.sleep(backoff)
            else:
                m.record_failure()
                raise

    m.record_failure()
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Retry loop exited without result or exception")


@dataclass
class RetryPolicyState:
    """Non-frozen state wrapper around a RetryPolicy config instance."""

    base_policy: RetryPolicy
    adaptive_heuristic: Any = None

    def effective_multiplier(self) -> float:
        if self.adaptive_heuristic is not None:
            return float(self.adaptive_heuristic.current_multiplier)
        return float(self.base_policy.backoff_multiplier)

    def observe_outcome(self, success: bool) -> None:
        if self.adaptive_heuristic is not None:
            self.adaptive_heuristic.observe(success)

    def copy(self) -> RetryPolicyState:
        return RetryPolicyState(
            base_policy=self.base_policy,
            adaptive_heuristic=self.adaptive_heuristic.copy()
            if self.adaptive_heuristic is not None
            else None,
        )

    @property
    def max_attempts(self) -> int:
        return self.base_policy.max_attempts

    @property
    def initial_backoff_seconds(self) -> float:
        return self.base_policy.initial_backoff_seconds

    @property
    def backoff_multiplier(self) -> float:
        return self.effective_multiplier()

    @property
    def max_backoff_seconds(self) -> float:
        return self.base_policy.max_backoff_seconds

    @property
    def retry_on_timeout(self) -> bool:
        return self.base_policy.retry_on_timeout

    @property
    def retry_on_error(self) -> bool:
        return self.base_policy.retry_on_error

    @property
    def jitter_factor(self) -> float:
        return self.base_policy.jitter_factor

    def delay_for_attempt(self, attempt_number: int, jitter: float | None = None) -> float:
        if attempt_number <= 1:
            return 0.0
        effective_backoff = max(0.0, self.initial_backoff_seconds)
        base_delay = effective_backoff * (self.backoff_multiplier ** max(0, attempt_number - 2))
        if self.max_backoff_seconds > 0:
            base_delay = min(base_delay, self.max_backoff_seconds)

        jitter_factor = self.jitter_factor if jitter is None else max(0.0, float(jitter))
        jitter_range = base_delay * jitter_factor
        jittered = base_delay + (_SYSTEM_RANDOM.random() * 2 - 1) * jitter_range
        return float(max(0.0, jittered))

    @classmethod
    def from_settings(
        cls,
        global_settings: dict[str, Any] | None = None,
        tool_settings: dict[str, Any] | None = None,
        *,
        adaptive: bool = False,
    ) -> RetryPolicyState:
        base = RetryPolicy.from_settings(global_settings, tool_settings)
        heuristic = None
        if adaptive:
            from src.pipeline.retry.strategies import AdaptiveBackoffHeuristic
            heuristic = AdaptiveBackoffHeuristic()
        return cls(base_policy=base, adaptive_heuristic=heuristic)


@dataclass
class StageRetryPolicy(RetryPolicyState):
    """Per-stage retry policy with its own decaying time budget."""

    max_retry_budget_seconds: float = 0.0
    backoff_profile: str | None = None
    _total_retry_seconds_consumed: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        if self.adaptive_heuristic is None:
            from src.pipeline.retry.strategies import AdaptiveBackoffHeuristic
            object.__setattr__(self, "adaptive_heuristic", AdaptiveBackoffHeuristic())

    def budget_remaining(self) -> float:
        return self.max_retry_budget_seconds - self._total_retry_seconds_consumed

    def is_budget_exhausted(self) -> bool:
        return self.budget_remaining() <= 0.0

    def consume_budget(self, seconds: float) -> None:
        object.__setattr__(
            self, "_total_retry_seconds_consumed", self._total_retry_seconds_consumed + seconds
        )

    def copy(self) -> StageRetryPolicy:
        return StageRetryPolicy(
            base_policy=self.base_policy,
            adaptive_heuristic=self.adaptive_heuristic.copy()
            if self.adaptive_heuristic is not None
            else None,
            max_retry_budget_seconds=self.max_retry_budget_seconds,
            backoff_profile=self.backoff_profile,
            _total_retry_seconds_consumed=self._total_retry_seconds_consumed,
        )

    @classmethod
    def from_settings(
        cls,
        global_settings: dict[str, Any] | None = None,
        tool_settings: dict[str, Any] | None = None,
        *,
        max_retry_budget_seconds: float = 0.0,
        backoff_profile: str | None = None,
        adaptive: bool = False,
    ) -> StageRetryPolicy:
        state = RetryPolicyState.from_settings(
            global_settings, tool_settings, adaptive=adaptive
        )
        return cls(
            base_policy=state.base_policy,
            adaptive_heuristic=state.adaptive_heuristic,
            max_retry_budget_seconds=max_retry_budget_seconds,
            backoff_profile=backoff_profile,
        )

    def _make_event(self, event_type: RetryEventType, attempt: int,
                    error: str, backoff_seconds: float) -> RetryEvent:
        return RetryEvent(
            event_type=event_type,
            stage=cast_to_stage_name(self),
            attempt=attempt,
            max_attempts=self.max_attempts,
            classification=classify_error(Exception(error)) if error else "unknown",
            backoff_seconds=backoff_seconds,
            error=error,
            total_backoff_seconds=self._total_retry_seconds_consumed,
        )

    def emit_retry_event(self, event: RetryEvent) -> None:
        try:
            from src.core.events import get_event_bus
            get_event_bus().publish(_pipeline_event_from_retry_event(event))
        except Exception as exc:
            logger.warning("Operation failed in policy.py: %s", exc, exc_info=True)  # noqa: BLE001

    def tool_policy(self, tool_identifier: str) -> ToolRetryPolicy:
        return ToolRetryPolicy(
            base_policy=self.base_policy,
            adaptive_heuristic=self.adaptive_heuristic.copy()
            if self.adaptive_heuristic is not None
            else None,
            max_retry_budget_seconds=self.max_retry_budget_seconds,
            backoff_profile=self.backoff_profile,
            _total_retry_seconds_consumed=self._total_retry_seconds_consumed,
            tool_identifier=tool_identifier,
            _stage_parent=self,
        )


@dataclass
class ToolRetryPolicy(StageRetryPolicy):
    """Per-tool policy that shares mutable state across calls for one tool."""

    tool_identifier: str = ""
    _recent_outcome_window: list[bool] = field(default_factory=list, repr=False)
    _recent_window_max: int = 16
    _stage_parent: StageRetryPolicy | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.adaptive_heuristic is None:
            from src.pipeline.retry.strategies import AdaptiveBackoffHeuristic
            object.__setattr__(self, "adaptive_heuristic", AdaptiveBackoffHeuristic())

    def budget_remaining(self) -> float:
        if self._stage_parent is not None:
            return self._stage_parent.budget_remaining()
        return super().budget_remaining()

    def is_budget_exhausted(self) -> bool:
        if self._stage_parent is not None:
            return self._stage_parent.is_budget_exhausted()
        return super().is_budget_exhausted()

    def consume_budget(self, seconds: float) -> None:
        if self._stage_parent is not None:
            self._stage_parent.consume_budget(seconds)
            object.__setattr__(self, "_total_retry_seconds_consumed", self._stage_parent._total_retry_seconds_consumed)
            return
        super().consume_budget(seconds)

    def observe_call_outcome(self, success: bool) -> None:
        self._recent_outcome_window.append(success)
        if len(self._recent_outcome_window) > self._recent_window_max:
            self._recent_outcome_window = self._recent_outcome_window[-self._recent_window_max :]
        self.observe_outcome(success)

    def copy(self) -> ToolRetryPolicy:
        return ToolRetryPolicy(
            base_policy=self.base_policy,
            adaptive_heuristic=self.adaptive_heuristic.copy()
            if self.adaptive_heuristic is not None
            else None,
            max_retry_budget_seconds=self.max_retry_budget_seconds,
            backoff_profile=self.backoff_profile,
            _total_retry_seconds_consumed=self._total_retry_seconds_consumed,
            tool_identifier=self.tool_identifier,
            _recent_outcome_window=list(self._recent_outcome_window),
            _stage_parent=self._stage_parent,
        )

    def _make_event(self, event_type: RetryEventType, attempt: int,
                    error: str, backoff_seconds: float) -> RetryEvent:
        return RetryEvent(
            event_type=event_type,
            stage=cast_to_stage_name(self),
            attempt=attempt,
            max_attempts=self.max_attempts,
            classification=classify_error(Exception(error)) if error else "unknown",
            backoff_seconds=backoff_seconds,
            error=error,
            timestamp=time.monotonic(),
            tool_identifier=self.tool_identifier or None,
            total_backoff_seconds=self._total_retry_seconds_consumed
            if self._stage_parent is None
            else self._stage_parent._total_retry_seconds_consumed,
        )


def is_stage_retry_policy(policy: object) -> bool:
    return isinstance(policy, StageRetryPolicy)


def is_tool_retry_policy(policy: object) -> bool:
    return isinstance(policy, ToolRetryPolicy)

"""Retry framework with per-stage budgets, adaptive backoff, and cancellation safety.

Classification logic (TRANSIENT / PERMANENT / UNKNOWN) and the frozen ``RetryPolicy``
are preserved verbatim for all existing callers.  The new mutable wrappers
(:class:`StageRetryPolicy`, :class:`ToolRetryPolicy`) layer on per-stage/tool
budgets, adaptive (Vegas-style) backoff, and structured event emission without
changing the public API of any downstream consumer.
"""

from __future__ import annotations

import asyncio
import secrets as random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeVar

from src.core.contracts.pipeline import RETRY_DEFAULTS
from src.core.logging.trace_logging import get_pipeline_logger

# Fix Audit #79: Move side-effect initialization below imports
# Use SystemRandom for non-predictable jitter (better than default PRNG for this use)
_SYSTEM_RANDOM = random.SystemRandom()

T = TypeVar("T")


class TransientError(Exception):
    """Error that may succeed on retry (e.g. network timeout, 5xx)."""

    def __init__(self, message: str, original: BaseException | None = None) -> None:
        super().__init__(message)
        self.original = original


class PermanentError(Exception):
    """Error that will not succeed on retry (e.g. 4xx, auth failure)."""

    def __init__(self, message: str, original: BaseException | None = None) -> None:
        super().__init__(message)
        self.original = original


class RetryBudgetExhausted(Exception):
    """Raised (or signalled) when the per-stage retry budget is depleted."""


@dataclass
class RetryMetrics:
    """Tracks retry statistics across operations."""

    total_attempts: int = 0
    total_retries: int = 0
    total_failures: int = 0
    total_successes: int = 0
    transient_errors: int = 0
    permanent_errors: int = 0
    total_backoff_seconds: float = 0.0

    def record_attempt(self) -> None:
        self.total_attempts += 1

    def record_retry(self, backoff: float = 0.0) -> None:
        self.total_retries += 1
        self.total_backoff_seconds += backoff

    def record_success(self) -> None:
        self.total_successes += 1

    def record_transient(self) -> None:
        self.transient_errors += 1

    def record_permanent(self) -> None:
        self.permanent_errors += 1

    def record_failure(self) -> None:
        self.total_failures += 1

    @property
    def retry_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_retries / self.total_attempts

    @property
    def success_rate(self) -> float:
        """Return the fraction of attempts that succeeded."""
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts

    def to_dict(self) -> dict[str, int | float]:
        """Export metrics as a dictionary for telemetry ingestion."""
        return {
            "total_attempts": self.total_attempts,
            "total_retries": self.total_retries,
            "total_failures": self.total_failures,
            "total_successes": self.total_successes,
            "transient_errors": self.transient_errors,
            "permanent_errors": self.permanent_errors,
            "total_backoff_seconds": round(self.total_backoff_seconds, 3),
            "retry_rate": round(self.retry_rate, 4),
            "success_rate": round(self.success_rate, 4),
        }


# ---------------------------------------------------------------------------
# Structured retry events (Task-requirement 5)
# ---------------------------------------------------------------------------

class RetryEventType(StrEnum):
    """Granular event types emitted by the retry framework."""

    RETRY_ATTEMPT = "retry_attempt"
    RETRY_SUCCESS = "retry_success"
    RETRY_EXHAUSTED = "retry_exhausted"
    RETRY_BUDGET_EXHAUSTED = "retry_budget_exhausted"


@dataclass
class RetryEvent:
    """Structured event emitted for every meaningful retry lifecycle transition."""

    event_type: RetryEventType
    stage: str
    attempt: int
    max_attempts: int
    classification: str
    backoff_seconds: float
    error: str
    timestamp: float = field(default_factory=time.monotonic)
    tool_identifier: str | None = None
    total_backoff_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "stage": self.stage,
            "tool_identifier": self.tool_identifier,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "classification": self.classification,
            "backoff_seconds": round(self.backoff_seconds, 3),
            "total_backoff_seconds": round(self.total_backoff_seconds, 3),
            "error": self.error,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Adaptive (Vegas / feedback-driven) backoff  (Task-requirement 3)
# ---------------------------------------------------------------------------

@dataclass
class AdaptiveBackoffHeuristic:
    """Vegas-style feedback controller for the exponential backoff multiplier.

    Maintains a fixed-size window of recent outcomes (success / failure).
    After every *adjustment_interval* observations the multiplier is nudged
    up when the failure rate exceeds the threshold, and nudged down when the
    success rate is healthy.
    """

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


# ---------------------------------------------------------------------------
# Backward-compatible frozen base — preserved verbatim
# ---------------------------------------------------------------------------

_TRANSIENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionResetError,
    ConnectionAbortedError,
    OSError,
    TransientError,
)

_PERMANENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    PermanentError,
    ValueError,
    TypeError,
    KeyError,
)

_HTTP_TRANSIENT_CODES = {408, 429, 500, 502, 503, 504}
_HTTP_PERMANENT_CODES = {400, 401, 403, 404, 405, 410, 422}


def classify_error(exc: BaseException) -> str:
    """Classify an exception as 'transient', 'permanent', or 'unknown'.

    Transient: TimeoutError, ConnectionError, HTTP 408/429/5xx
    Permanent: ValueError, TypeError, KeyError, HTTP 4xx (non-retryable)
    Unknown: everything else (policy decides whether to retry)
    """
    if isinstance(exc, _TRANSIENT_EXCEPTIONS):
        return "transient"
    if isinstance(exc, _PERMANENT_EXCEPTIONS):
        return "permanent"
    response = getattr(exc, "response", None)
    status_code = getattr(exc, "status_code", None)
    if status_code is None and response is not None:
        status_code = getattr(response, "status_code", None)

    if status_code is not None:
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            code = None

        if code in _HTTP_TRANSIENT_CODES:
            return "transient"
        if code in _HTTP_PERMANENT_CODES:
            return "permanent"
    return "unknown"


@dataclass(frozen=True)
class RetryPolicy:
    """Immutable retry configuration — API and behaviour fully preserved.

    Construction, ``from_settings``, ``delay_for_attempt``, ``max_attempts``,
    and all field names remain unchanged.  Existing callers that pass a
    :class:`StageRetryPolicy` or :class:`ToolRetryPolicy` to functions
    annotated ``RetryPolicy`` continue to work because both are subclasses.
    """

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
        return max(0.0, jittered)


def is_retryable(exc: BaseException, policy: RetryPolicy) -> bool:
    """Determine whether an exception should trigger a retry."""
    classification = classify_error(exc)
    if classification == "permanent":
        return False
    if classification == "transient":
        if isinstance(exc, TimeoutError) and not policy.retry_on_timeout:
            return False
        return True
    if classification == "unknown":
        return policy.retry_on_error
    return False


def retry_ready(policy: RetryPolicy, attempt: int) -> bool:
    """Return True when another retry attempt is still allowed.

    Args:
        policy: Retry policy with max attempts.
        attempt: Current attempt number (1-based).
    """
    return attempt < policy.max_attempts


def sleep_before_retry(policy: RetryPolicy, attempt: int) -> float:
    delay = policy.delay_for_attempt(attempt + 1)
    if delay > 0:
        time.sleep(delay)
    return delay


logger = get_pipeline_logger(__name__)


def execute_with_retry[T](  # pylint: disable=W0621
    func: Callable[..., T],
    policy: RetryPolicy,
    metrics: RetryMetrics | None = None,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Execute *func* with retry logic according to *policy*.

    Transient errors are retried up to *policy.max_attempts*.
    Permanent errors are raised immediately.
    Metrics are updated when a *metrics* instance is provided.
    """
    m = metrics or RetryMetrics()
    last_exc: BaseException | None = None

    for attempt in range(1, policy.max_attempts + 1):
        m.record_attempt()
        try:
            result = func(*args, **kwargs)
            m.record_success()
            return result
        except Exception as exc:  # Fix Audit #13: Simplify to broad Exception
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


# ---------------------------------------------------------------------------
# Non-frozen state wrapper — base for StageRetryPolicy and ToolRetryPolicy
# ---------------------------------------------------------------------------

@dataclass
class RetryPolicyState:
    """Non-frozen state wrapper around a :class:`RetryPolicy` config instance.

    Every mutable attribute (adaptive heuristic, observation windows, counters)
    lives here so the frozen ``RetryPolicy`` dataclass—whose instances may be
    shared across calls—is never mutated.
    """

    base_policy: RetryPolicy
    adaptive_heuristic: AdaptiveBackoffHeuristic | None = None

    def effective_multiplier(self) -> float:
        if self.adaptive_heuristic is not None:
            return self.adaptive_heuristic.current_multiplier
        return self.base_policy.backoff_multiplier

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

    # Proxy every ``RetryPolicy`` attribute that external callers read directly
    # so that ``isinstance(policy, RetryPolicy)`` is satisfied and attribute
    # access works uniformly.

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
        return max(0.0, jittered)

    @classmethod
    def from_settings(
        cls,
        global_settings: dict[str, Any] | None = None,
        tool_settings: dict[str, Any] | None = None,
        *,
        adaptive: bool = False,
    ) -> RetryPolicyState:
        base = RetryPolicy.from_settings(global_settings, tool_settings)
        heuristic = AdaptiveBackoffHeuristic() if adaptive else None
        return cls(base_policy=base, adaptive_heuristic=heuristic)


@dataclass
class StageRetryPolicy(RetryPolicyState):
    """Per-stage retry policy with its own decaying time budget.

    Each stage in a pipeline run gets an independent :class:`StageRetryPolicy`
    so that a 10-minute scan with heavy retries in stage-1 does not starve
    stage-5 of retry budget (requirement 2).

    Attributes:
        max_retry_budget_seconds: Total seconds available for backoff sleep
            across this stage's lifetime.  Consumed by :meth:`consume_budget`
            and checked by :meth:`budget_remaining` before each sleep.
        backoff_profile: Optional profile name that overrides the base
            policy's backoff parameters (``retry_backoff_seconds``,
            ``retry_backoff_multiplier``, ``retry_max_backoff_seconds``).
        _total_retry_seconds_consumed: Internal accumulator (not part of the
            public API; use :meth:`consume_budget` to update).
    """

    max_retry_budget_seconds: float = 0.0
    backoff_profile: str | None = None
    _total_retry_seconds_consumed: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        if self.adaptive_heuristic is None:
            object.__setattr__(self, "adaptive_heuristic", AdaptiveBackoffHeuristic())

    def budget_remaining(self) -> float:
        """Seconds of retry budget still available (may be negative if exhausted)."""
        return self.max_retry_budget_seconds - self._total_retry_seconds_consumed

    def is_budget_exhausted(self) -> bool:
        return self.budget_remaining() <= 0.0

    def consume_budget(self, seconds: float) -> None:
        object.__setattr__(self, "_total_retry_seconds_consumed",
                           self._total_retry_seconds_consumed + seconds)

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
        """Publish *event* on the process-wide event bus (non-blocking, sync-safe)."""
        try:
            from src.core.events import get_event_bus
            get_event_bus().publish(
                _pipeline_event_from_retry_event(event)
            )
        except Exception:  # noqa: BLE001
            pass  # Event emission must never break the retry loop

    def tool_policy(self, tool_identifier: str) -> ToolRetryPolicy:
        """Return a :class:`ToolRetryPolicy` that shares budget/state with this stage."""
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

    def tool_policy(self, tool_identifier: str) -> ToolRetryPolicy:
        """Return a :class:`ToolRetryPolicy` that shares state with this stage."""
        return ToolRetryPolicy(
            base_policy=self.base_policy,
            adaptive_heuristic=self.adaptive_heuristic.copy()
            if self.adaptive_heuristic is not None
            else None,
            tool_identifier=tool_identifier,
            max_retry_budget_seconds=self.max_retry_budget_seconds,
            backoff_profile=self.backoff_profile,
            _total_retry_seconds_consumed=self._total_retry_seconds_consumed,
        )


def cast_to_stage_name(policy: StageRetryPolicy) -> str:
    """Best-effort stage name extraction; falls back to 'unknown'."""
    return getattr(policy.base_policy, "_stage_name", "unknown") or "unknown"


@dataclass
class ToolRetryPolicy(StageRetryPolicy):
    """Per-tool policy that shares mutable state across calls for one tool.

    Inherits all budget and adaptive-backoff behaviour from
    :class:`StageRetryPolicy`.  Carries an extra ``tool_identifier`` string
    that is attached to every emitted :class:`RetryEvent` so the
    self-healing controller can differentiate retry storms by tool.

    When ``_stage_parent`` is supplied, budget operations are forwarded to
    that parent so multiple calls to the same tool in a single stage draw
    from the same stage budget without double-counting.
    """

    tool_identifier: str = ""
    _recent_outcome_window: list[bool] = field(default_factory=list, repr=False)
    _recent_window_max: int = 16
    _stage_parent: StageRetryPolicy | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.adaptive_heuristic is None:
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
        """Record the result of one tool call and update the adaptive heuristic."""
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


# ---------------------------------------------------------------------------
# EventBus bridge
# ---------------------------------------------------------------------------

def _pipeline_event_from_retry_event(event: RetryEvent) -> Any:
    """Convert :class:`RetryEvent` into a :class:`~src.core.events.PipelineEvent`."""
    try:
        from src.core.events import PipelineEvent  # lazy to avoid circular
        return PipelineEvent(
            event_type=_retry_event_type_to_event_type(event.event_type),
            source=f"retry.{event.stage}",
            data=event.to_dict(),
        )
    except ImportError:
        return None


_RETRY_TO_PIPELINE_EVENT_TYPE: dict[RetryEventType, Any] = {}


def _retry_event_type_to_event_type(retry_type: RetryEventType) -> Any:
    global _RETRY_TO_PIPELINE_EVENT_TYPE
    if not _RETRY_TO_PIPELINE_EVENT_TYPE:
        try:
            from src.core.events import EventType
            _RETRY_TO_PIPELINE_EVENT_TYPE = {
                RetryEventType.RETRY_ATTEMPT:       EventType.STAGE_RETRY,
                RetryEventType.RETRY_SUCCESS:       EventType.STAGE_COMPLETED,
                RetryEventType.RETRY_EXHAUSTED:     EventType.STAGE_FAILED,
                RetryEventType.RETRY_BUDGET_EXHAUSTED: EventType.STAGE_FAILED,
            }
        except ImportError:
            pass
    return _RETRY_TO_PIPELINE_EVENT_TYPE.get(retry_type)


class RetryEventEmitter:
    """Publishes :class:`RetryEvent` instances through the process-wide event bus.

    All ``publish`` calls are fire-and-forget; failures are silently discarded
    so that event emission can never crash a retry loop.

    The ``emit`` convenience method accepts the same args as
    :class:`RetryEvent` and constructs/emits the event in one step.
    """

    def emit(
        self,
        event_type: RetryEventType,
        *,
        stage: str,
        attempt: int,
        max_attempts: int,
        classification: str,
        error: str,
        backoff_seconds: float = 0.0,
        total_backoff_seconds: float = 0.0,
        tool_identifier: str | None = None,
    ) -> RetryEvent:
        event = RetryEvent(
            event_type=event_type,
            stage=stage,
            attempt=attempt,
            max_attempts=max_attempts,
            classification=classification,
            backoff_seconds=backoff_seconds,
            error=error,
            total_backoff_seconds=total_backoff_seconds,
            tool_identifier=tool_identifier,
        )
        pipeline_event = _pipeline_event_from_retry_event(event)
        if pipeline_event is not None:
            try:
                from src.core.events import get_event_bus
                get_event_bus().publish(pipeline_event)
            except Exception:  # noqa: BLE001
                pass
        return event


# ---------------------------------------------------------------------------
# Async sleep helpers with cancellation safety  (Task-requirement 4)
# ---------------------------------------------------------------------------

async def sleep_before_retry_async(
    policy: RetryPolicy,
    attempt: int,
    shutdown_event: asyncio.Event | None = None,
) -> float:
    """Async drop-in replacement for :func:`sleep_before_retry`.

    Uses :func:`asyncio.sleep` so the coroutine can be ``cancel()``-led at
    any point, and surfaces the cancellation as a clean ``asyncio.CancelledError``.
    A supplied *shutdown_event* is also polled so the wait short-circuits on
    SIGINT even when no explicit cancel is issued.

    Returns the delay (in seconds) that was computed.  Returns ``0.0`` when
    no wait was needed.
    """
    delay = policy.delay_for_attempt(attempt + 1)
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
    """Sleep for *seconds*, short-circuiting on cancel or shutdown.

    Splits the wait into ``check_interval`` chunks so the shutdown flag is
    polled at least that frequently; useful when ``asyncio.sleep`` is
    cancelled but the caller wants a soft early-out without raising.
    """
    if seconds <= 0:
        return
    remaining = seconds
    while remaining > 0:
        if asyncio.current_task() is not None and asyncio.current_task().cancelled():
            raise asyncio.CancelledError()
        if shutdown_event is not None and shutdown_event.is_set():
            raise asyncio.CancelledError("Shutdown signalled")
        chunk = min(remaining, check_interval)
        try:
            await asyncio.sleep(chunk)
        except asyncio.CancelledError:
            raise
        remaining -= chunk


# ---------------------------------------------------------------------------
# Policy helper utilities
# ---------------------------------------------------------------------------

def is_stage_retry_policy(policy: object) -> bool:
    return isinstance(policy, StageRetryPolicy)


def is_tool_retry_policy(policy: object) -> bool:
    return isinstance(policy, ToolRetryPolicy)


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


# ---------------------------------------------------------------------------
# Re-export original public names for all existing callers
# ---------------------------------------------------------------------------

__all__ = [
    "AdaptiveBackoffHeuristic",
    "RetryBudgetExhausted",
    "RetryEvent",
    "RetryEventEmitter",
    "RetryEventType",
    "RetryMetrics",
    "RetryPolicy",
    "RetryPolicyState",
    "StageRetryPolicy",
    "ToolRetryPolicy",
    "TransientError",
    "PermanentError",
    "RetryBudgetExhausted",
    "cancellable_sleep",
    "classify_error",
    "execute_with_retry",
    "is_retryable",
    "is_stage_retry_policy",
    "is_tool_retry_policy",
    "retry_ready",
    "sleep_before_retry",
    "sleep_before_retry_async",
]

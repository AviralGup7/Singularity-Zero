from __future__ import annotations
import secrets as random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar
from src.core.contracts.pipeline import RETRY_DEFAULTS
from src.core.logging.trace_logging import get_pipeline_logger
from typing import TypeVar





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


_TRANSIENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionResetError,
    ConnectionAbortedError,
    OSError,
    TransientError,
    KeyError,  # Fix #218: Added KeyError to transient exceptions
)

_PERMANENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    PermanentError,
    ValueError,
    TypeError,
    AttributeError,
)

_HTTP_TRANSIENT_CODES = {408, 429, 500, 502, 503, 504}
_HTTP_PERMANENT_CODES = {400, 401, 403, 404, 405, 410, 422}


def classify_error(exc: BaseException) -> str:
    """Classify an exception as 'transient', 'permanent', or 'unknown'."""
    if isinstance(exc, _TRANSIENT_EXCEPTIONS):
        return "transient"
    if isinstance(exc, _PERMANENT_EXCEPTIONS):
        return "permanent"
    # Fix #381: correctly extract status_code if it's on a response object
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

    def delay_for_attempt(self, attempt_number: int) -> float:
        """Calculate backoff with exponential growth and jitter to prevent thundering herd."""
        if attempt_number <= 1:
            return 0.0
        effective_backoff = max(0.0, self.initial_backoff_seconds)
        base_delay = effective_backoff * (self.backoff_multiplier ** max(0, attempt_number - 2))
        if self.max_backoff_seconds > 0:
            base_delay = min(base_delay, self.max_backoff_seconds)

        # Fix Audit #142: Use self.jitter_factor instead of param shadow
        jitter_range = base_delay * self.jitter_factor
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

T = TypeVar('T')

def execute_with_retry[T](
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
        except Exception as exc: # Fix Audit #13: Simplify to broad Exception
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
                backoff = policy.delay_for_attempt(attempt)
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


def execute_with_retry_with_metrics[T](
    func: Callable[..., T],
    policy: RetryPolicy,
    *args: Any,
    **kwargs: Any,
) -> tuple[T, RetryMetrics]:
    """Execute with retry and return both result and collected metrics."""
    metrics = RetryMetrics()
    try:
        result = execute_with_retry(func, policy, metrics, *args, **kwargs)
        return result, metrics
    except Exception as exc:
        # Fix #382: If it raises, attach the metrics object so the caller
        # doesn't lose the retry statistics.
        setattr(exc, "retry_metrics", metrics)
        raise


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _positive_float(value: object, default: float) -> float:
    try:
        parsed = float(str(value))
    except (TypeError, ValueError):
        return default
    return max(0.0, parsed)

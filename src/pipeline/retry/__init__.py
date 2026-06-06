"""Retry framework with per-stage budgets, adaptive backoff, and cancellation safety."""

from __future__ import annotations

from src.pipeline.retry.classifier import PermanentError, TransientError, classify_error
from src.pipeline.retry.events import (
    RetryEvent,
    RetryEventEmitter,
    RetryEventType,
)
from src.pipeline.retry.metrics import RetryBudgetExhausted, RetryMetrics
from src.pipeline.retry.policy import (
    RetryPolicy,
    RetryPolicyState,
    StageRetryPolicy,
    ToolRetryPolicy,
    execute_with_retry,
    is_stage_retry_policy,
    is_tool_retry_policy,
)
from src.pipeline.retry.strategies import (
    AdaptiveBackoffHeuristic,
    cancellable_sleep,
    is_retryable,
    retry_ready,
    sleep_before_retry,
    sleep_before_retry_async,
)

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

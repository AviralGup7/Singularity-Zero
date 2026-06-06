"""Structured retry events, event emitter, and event-bus bridge helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic
from typing import Any

_RETRY_TO_PIPELINE_EVENT_TYPE: dict[Any, Any] = {}


class RetryEventType(StrEnum):
    RETRY_ATTEMPT = "retry_attempt"
    RETRY_SUCCESS = "retry_success"
    RETRY_EXHAUSTED = "retry_exhausted"
    RETRY_BUDGET_EXHAUSTED = "retry_budget_exhausted"


@dataclass
class RetryEvent:
    event_type: RetryEventType
    stage: str
    attempt: int
    max_attempts: int
    classification: str
    backoff_seconds: float
    error: str
    timestamp: float = field(default_factory=monotonic)
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


def _retry_event_type_to_event_type(retry_type: RetryEventType) -> Any:
    global _RETRY_TO_PIPELINE_EVENT_TYPE
    if not _RETRY_TO_PIPELINE_EVENT_TYPE:
        try:
            from src.core.events import EventType
            _RETRY_TO_PIPELINE_EVENT_TYPE = {
                RetryEventType.RETRY_ATTEMPT: EventType.STAGE_RETRY,
                RetryEventType.RETRY_SUCCESS: EventType.STAGE_COMPLETED,
                RetryEventType.RETRY_EXHAUSTED: EventType.STAGE_FAILED,
                RetryEventType.RETRY_BUDGET_EXHAUSTED: EventType.STAGE_FAILED,
            }
        except ImportError:
            pass
    return _RETRY_TO_PIPELINE_EVENT_TYPE.get(retry_type)


def _pipeline_event_from_retry_event(event: RetryEvent) -> Any:
    try:
        from src.core.events import PipelineEvent
        return PipelineEvent(
            event_type=_retry_event_type_to_event_type(event.event_type),
            source=f"retry.{event.stage}",
            data=event.to_dict(),
        )
    except ImportError:
        return None


class RetryEventEmitter:
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
        try:
            from src.core.events import get_event_bus
            get_event_bus().publish(_pipeline_event_from_retry_event(event))
        except Exception:
            pass
        return event

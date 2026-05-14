"""Span and tracing data models.

Provides Span, SpanEvent, SpanLink dataclasses, the SpanStatus enum,
and W3C TraceContext serialization utilities.
"""

from __future__ import annotations

import contextvars
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

_current_span: contextvars.ContextVar[Span | None] = contextvars.ContextVar(
    "current_span", default=None
)
_current_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_trace_id", default=None
)


class SpanStatus(StrEnum):
    """Status of a span."""

    UNSET = "unset"
    OK = "ok"
    ERROR = "error"


@dataclass
class SpanEvent:
    """A timestamped event within a span."""

    name: str
    timestamp: float
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class SpanLink:
    """A link from one span to another."""

    trace_id: str
    span_id: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Span:
    """Represents a single operation within a trace.

    Spans form a parent-child hierarchy within a trace.
    """

    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    status: SpanStatus = SpanStatus.UNSET
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[SpanEvent] = field(default_factory=list)
    links: list[SpanLink] = field(default_factory=list)

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_attributes(self, attrs: dict[str, Any]) -> None:
        self.attributes.update(attrs)

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        self.events.append(SpanEvent(name=name, timestamp=time.time(), attributes=attributes or {}))

    def add_link(
        self, trace_id: str, span_id: str, attributes: dict[str, Any] | None = None
    ) -> None:
        self.links.append(SpanLink(trace_id=trace_id, span_id=span_id, attributes=attributes or {}))

    def record_error(self, error: BaseException) -> None:
        self.status = SpanStatus.ERROR
        self.add_event(
            "exception",
            {
                "exception.type": type(error).__name__,
                "exception.message": str(error),
            },
        )

    def end(self) -> None:
        self.end_time = time.time()
        if self.status == SpanStatus.UNSET:
            self.status = SpanStatus.OK

    @property
    def duration_ms(self) -> float:
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time) * 1000

    @property
    def duration_s(self) -> float:
        if self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "attributes": self.attributes,
            "events": [
                {"name": e.name, "timestamp": e.timestamp, "attributes": e.attributes}
                for e in self.events
            ],
            "links": [
                {"trace_id": link.trace_id, "span_id": link.span_id, "attributes": link.attributes}
                for link in self.links
            ],
        }

    def to_w3c_traceparent(self) -> str:
        flags = "01" if self.status == SpanStatus.ERROR else "00"
        return f"00-{self.trace_id}-{self.span_id}-{flags}"

    @classmethod
    def from_w3c_traceparent(cls, traceparent: str) -> tuple[str, str, bool]:
        parts = traceparent.split("-")
        if len(parts) != 4:
            raise ValueError(f"Invalid traceparent header: {traceparent}")
        version, trace_id, parent_id, flags = parts
        sampled = flags[-1] in ("1", "2", "3")
        return trace_id, parent_id, sampled

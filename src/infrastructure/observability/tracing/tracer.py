"""Core tracer with span creation and context propagation.

Provides the Tracer class that creates spans with parent-child
relationships, manages trace context via context variables, and
exports spans to configured backends.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from src.infrastructure.observability.config import get_config
from src.infrastructure.observability.tracing.exporters import (
    InMemoryExporter,
    OTLPExporter,
)
from src.infrastructure.observability.tracing.models import (
    Span,
    SpanLink,
    _current_span,
    _current_trace_id,
)
from src.infrastructure.observability.tracing.sampling import SamplingDecision


class Tracer:
    """Distributed tracer with span creation and context propagation."""

    def __init__(
        self,
        service_name: str = "cyber-security-pipeline",
        sampling: SamplingDecision | None = None,
        exporter: InMemoryExporter | OTLPExporter | None = None,
        max_attributes: int = 128,
        max_events: int = 128,
        max_links: int = 128,
    ) -> None:
        self.service_name = service_name
        self.sampling = sampling or SamplingDecision()
        self.exporter = exporter or InMemoryExporter()
        self.max_attributes = max_attributes
        self.max_events = max_events
        self.max_links = max_links
        self._spans: list[Span] = []

    @contextmanager
    def start_span(
        self,
        name: str,
        trace_id: str | None = None,
        attributes: dict[str, Any] | None = None,
        links: list[SpanLink] | None = None,
        force_sample: bool = False,
    ) -> Generator[Span]:
        parent = _current_span.get()
        existing_trace_id = _current_trace_id.get()

        if trace_id is None:
            if existing_trace_id:
                trace_id = existing_trace_id
            else:
                trace_id = uuid.uuid4().hex

        sampled = force_sample or self.sampling.should_sample(trace_id)

        span_id = uuid.uuid4().hex[:16]
        parent_span_id = parent.span_id if parent else None

        span = Span(
            name=name,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            attributes={"service.name": self.service_name},
        )

        if attributes:
            for k, v in attributes.items():
                if len(span.attributes) < self.max_attributes:
                    span.set_attribute(k, v)

        if links:
            for link in links[: self.max_links]:
                span.links.append(link)

        if parent:
            span.add_link(parent.trace_id, parent.span_id)

        token = _current_span.set(span)
        trace_token = _current_trace_id.set(trace_id)

        try:
            yield span
        except BaseException as e:
            span.record_error(e)
            raise
        finally:
            span.end()
            _current_span.reset(token)
            _current_trace_id.reset(trace_token)

            if sampled:
                self._spans.append(span)
                if isinstance(self.exporter, (InMemoryExporter, OTLPExporter)):
                    self.exporter.export([span])

    def create_span(
        self,
        name: str,
        trace_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Span:
        parent = _current_span.get()
        existing_trace_id = _current_trace_id.get()

        if trace_id is None:
            trace_id = existing_trace_id or uuid.uuid4().hex

        span_id = uuid.uuid4().hex[:16]
        span = Span(
            name=name,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent.span_id if parent else None,
            attributes={"service.name": self.service_name},
        )

        if attributes:
            span.set_attributes(attributes)

        return span

    def inject_context(self, span: Span) -> dict[str, str]:
        return {"traceparent": span.to_w3c_traceparent()}

    def extract_context(self, headers: dict[str, str]) -> tuple[str, str | None, bool]:
        traceparent = headers.get("traceparent", "")
        if not traceparent:
            return uuid.uuid4().hex, None, True
        return Span.from_w3c_traceparent(traceparent)

    def get_current_span(self) -> Span | None:
        return _current_span.get()

    def get_current_trace_id(self) -> str | None:
        return _current_trace_id.get()

    def get_all_spans(self) -> list[Span]:
        return list(self._spans)

    def get_spans_by_name(self, name: str) -> list[Span]:
        return [span for span in self._spans if span.name == name]

    def get_spans_by_trace(self, trace_id: str) -> list[Span]:
        return [span for span in self._spans if span.trace_id == trace_id]

    def get_error_spans(self) -> list[Span]:
        from src.infrastructure.observability.tracing.models import SpanStatus

        return [s for s in self._spans if s.status == SpanStatus.ERROR]

    def get_trace_tree(self, trace_id: str) -> dict[str, Any]:
        spans = self.get_spans_by_trace(trace_id)
        span_map: dict[str, Any] = {}
        roots: list[Span] = []

        for span in spans:
            node = {"span": span.to_dict(), "children": []}
            span_map[span.span_id] = node
            if span.parent_span_id is None:
                roots.append(span)
            else:
                parent = span_map.get(span.parent_span_id)
                if parent:
                    parent["children"].append(node)

        return {
            "trace_id": trace_id,
            "root_spans": [span_map[r.span_id] for r in roots],
            "total_spans": len(spans),
            "error_count": len(
                self.get_spans_by_trace(trace_id)
                and [s for s in spans if s.status.value == "error"]
            ),
            "total_duration_ms": max((s.duration_ms for s in roots), default=0),
        }

    def clear(self) -> None:
        self._spans.clear()

    def get_stats(self) -> dict[str, Any]:
        error_spans = len(self.get_error_spans())
        unique_traces = len(set(s.trace_id for s in self._spans))
        return {
            "total_spans": len(self._spans),
            "error_spans": error_spans,
            "unique_traces": unique_traces,
            # Backward-compatible alias retained for existing dashboards/tests.
            "trace_count": unique_traces,
            "service_name": self.service_name,
            "exporter_stats": self.exporter.get_stats() if self.exporter else None,
        }


_tracer_instance: Tracer | None = None


def get_tracer() -> Tracer:
    global _tracer_instance
    if _tracer_instance is None:
        config = get_config()
        sampling = SamplingDecision(
            strategy=config.tracing.sampling_strategy,
            rate=config.tracing.sampling_rate,
        )
        if config.tracing.otlp_endpoint:
            exporter: InMemoryExporter | OTLPExporter = OTLPExporter(
                endpoint=config.tracing.otlp_endpoint,
            )
        else:
            exporter = InMemoryExporter(max_traces=config.tracing.max_traces_in_memory)

        _tracer_instance = Tracer(
            service_name=config.tracing.service_name,
            sampling=sampling,
            exporter=exporter,
        )
    return _tracer_instance

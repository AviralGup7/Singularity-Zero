"""Trace exporter backends.

Provides InMemoryExporter for development and OTLPExporter for
production-compatible trace collection.
"""

from __future__ import annotations

import time
from typing import Any

from src.infrastructure.observability.tracing.models import Span, SpanStatus


class InMemoryExporter:
    """In-memory trace exporter for development."""

    def __init__(self, max_traces: int = 1000) -> None:
        self._traces: dict[str, list[Span]] = {}
        self._max_traces = max_traces

    def export(self, spans: list[Span]) -> None:
        for span in spans:
            if span.trace_id not in self._traces:
                if len(self._traces) >= self._max_traces:
                    oldest_key = next(iter(self._traces))
                    del self._traces[oldest_key]
                self._traces[span.trace_id] = []
            self._traces[span.trace_id].append(span)

    def get_trace(self, trace_id: str) -> list[Span] | None:
        return self._traces.get(trace_id)

    def get_all_traces(self) -> dict[str, list[Span]]:
        return dict(self._traces)

    def search(self, **filters: Any) -> list[Span]:
        results: list[Span] = []
        for spans in self._traces.values():
            for span in spans:
                if all(span.attributes.get(k) == v for k, v in filters.items()):
                    results.append(span)
        return results

    def clear(self) -> None:
        self._traces.clear()

    def get_stats(self) -> dict[str, Any]:
        total_spans = sum(len(spans) for spans in self._traces.values())
        return {
            "trace_count": len(self._traces),
            "span_count": total_spans,
            "max_traces": self._max_traces,
        }


class OTLPExporter:
    """OTLP trace exporter for production (Jaeger, Zipkin, Tempo, etc.).

    Falls back to no-op if opentelemetry-exporter-otlp is not installed.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:4317",
        insecure: bool = True,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.insecure = insecure
        self.headers = headers or {}
        self._available = False
        self._exporter: Any = None
        self._pending_spans: list[Span] = []
        self._export_count = 0
        self._error_count = 0
        self._try_init()

    def _try_init(self) -> None:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            self._exporter = OTLPSpanExporter(
                endpoint=self.endpoint,
                insecure=self.insecure,
                headers=self.headers,
            )
            self._available = True
        except ImportError:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )

                self._exporter = OTLPSpanExporter(
                    endpoint=self.endpoint,
                    headers=self.headers,
                )
                self._available = True
            except ImportError:
                self._available = False

    def export(self, spans: list[Span]) -> None:
        if not self._available:
            self._pending_spans.extend(spans)
            return
        try:
            otel_spans = self._convert_to_otel(spans)
            if otel_spans:
                self._exporter.export(otel_spans)
                self._export_count += 1
        except Exception:
            self._error_count += 1

    def _convert_to_otel(self, spans: list[Span]) -> list[Any]:
        try:
            from opentelemetry.sdk.trace import ReadableSpan
            from opentelemetry.trace import SpanContext, Status, StatusCode, TraceFlags
        except ImportError:
            return []

        otel_spans: list[Any] = []
        for span in spans:
            trace_id = int(span.trace_id, 16)
            span_id = int(span.span_id, 16)
            parent_id = int(span.parent_span_id, 16) if span.parent_span_id else None

            trace_flags = TraceFlags.SAMPLED
            span_context = SpanContext(
                trace_id=trace_id,
                span_id=span_id,
                is_remote=False,
                trace_flags=trace_flags,
            )

            if span.status == SpanStatus.ERROR:
                otel_status = Status(StatusCode.ERROR)
            elif span.status == SpanStatus.OK:
                otel_status = Status(StatusCode.OK)
            else:
                otel_status = Status(StatusCode.UNSET)

            otel_span = ReadableSpan(
                name=span.name,
                context=span_context,
                parent=SpanContext(
                    trace_id=trace_id,
                    span_id=parent_id or 0,
                    is_remote=False,
                    trace_flags=trace_flags,
                )
                if parent_id
                else None,
                start_time=int(span.start_time * 1e9),
                end_time=int((span.end_time or time.time()) * 1e9),
                status=otel_status,
                attributes=dict(span.attributes) if span.attributes else None,
            )
            otel_spans.append(otel_span)

        return otel_spans

    def flush(self) -> None:
        if self._pending_spans and self._available:
            self.export(self._pending_spans)
            self._pending_spans.clear()

    def shutdown(self) -> None:
        self.flush()
        if self._exporter is not None:
            try:
                self._exporter.shutdown()
            except Exception:
                pass

    @property
    def is_available(self) -> bool:
        return self._available

    def get_stats(self) -> dict[str, Any]:
        return {
            "available": self._available,
            "export_count": self._export_count,
            "error_count": self._error_count,
            "pending_spans": len(self._pending_spans),
        }

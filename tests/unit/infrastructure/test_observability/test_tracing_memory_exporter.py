import unittest

from src.infrastructure.observability.tracing import (
    InMemoryExporter,
    Span,
)


class TestInMemoryExporter(unittest.TestCase):
    def test_export_and_retrieve(self) -> None:
        exporter = InMemoryExporter()
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.end()
        exporter.export([span])
        trace = exporter.get_trace("t1")
        assert trace is not None
        assert len(trace) == 1

    def test_search(self) -> None:
        exporter = InMemoryExporter()
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.set_attribute("service", "api")
        span.end()
        exporter.export([span])
        results = exporter.search(service="api")
        assert len(results) == 1

    def test_clear(self) -> None:
        exporter = InMemoryExporter()
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.end()
        exporter.export([span])
        exporter.clear()
        assert exporter.get_all_traces() == {}

    def test_max_traces(self) -> None:
        exporter = InMemoryExporter(max_traces=2)
        for i in range(5):
            span = Span(name="test", trace_id=f"t{i}", span_id=f"s{i}")
            span.end()
            exporter.export([span])
        assert len(exporter.get_all_traces()) <= 2

    def test_get_stats(self) -> None:
        exporter = InMemoryExporter()
        stats = exporter.get_stats()
        assert "trace_count" in stats
        assert "span_count" in stats

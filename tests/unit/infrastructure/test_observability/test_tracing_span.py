import unittest

import pytest

from src.infrastructure.observability.tracing import (
    Span,
    SpanStatus,
)


class TestSpan(unittest.TestCase):
    def test_span_defaults(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        assert span.name == "test"
        assert span.status == SpanStatus.UNSET
        assert span.parent_span_id is None
        assert span.end_time is None

    def test_set_attribute(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.set_attribute("key", "value")
        assert span.attributes["key"] == "value"

    def test_set_attributes(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.set_attributes({"a": 1, "b": 2})
        assert span.attributes["a"] == 1
        assert span.attributes["b"] == 2

    def test_add_event(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.add_event("my_event", {"detail": "info"})
        assert len(span.events) == 1
        assert span.events[0].name == "my_event"

    def test_add_link(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.add_link("t2", "s2")
        assert len(span.links) == 1
        assert span.links[0].trace_id == "t2"

    def test_record_error(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.record_error(ValueError("test error"))
        assert span.status == SpanStatus.ERROR
        assert len(span.events) == 1
        assert span.events[0].name == "exception"

    def test_end(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        span.end()
        assert span.end_time is not None
        assert span.status == SpanStatus.OK

    def test_duration_ms(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        assert span.duration_ms == 0.0
        span.end()
        assert span.duration_ms >= 0.0

    def test_to_dict(self) -> None:
        span = Span(name="test", trace_id="t1", span_id="s1")
        d = span.to_dict()
        assert d["name"] == "test"
        assert d["trace_id"] == "t1"
        assert d["span_id"] == "s1"

    def test_w3c_traceparent(self) -> None:
        span = Span(name="test", trace_id="a" * 32, span_id="b" * 16)
        span.end()
        tp = span.to_w3c_traceparent()
        assert tp.startswith("00-")

    def test_from_w3c_traceparent(self) -> None:
        trace_id, parent_id, sampled = Span.from_w3c_traceparent("00-abc123-def456-01")
        assert trace_id == "abc123"
        assert parent_id == "def456"
        assert sampled is True

    def test_from_w3c_traceparent_invalid(self) -> None:
        with pytest.raises(ValueError):
            Span.from_w3c_traceparent("invalid")

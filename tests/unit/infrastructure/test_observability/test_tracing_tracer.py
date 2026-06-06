import asyncio
import unittest
import pytest
from src.infrastructure.observability.alerts import (
    Alert,
    AlertChannel,
    AlertManager,
    AlertRule,
    AlertSeverity,
    AlertState,
    ChannelType,
)
from src.infrastructure.observability.config import (
    AlertConfig,
    Environment,
    HealthCheckConfig,
    LogLevel,
    MetricsConfig,
    ObservabilityConfig,
    SamplingStrategy,
    TracingConfig,
)
from src.infrastructure.observability.health_checks import (
    ComponentHealth,
    ComponentStatus,
    HealthChecker,
    HealthCheckResult,
    HealthStatus,
)
from src.infrastructure.observability.metrics import (
    CounterMetric,
    GaugeMetric,
    HistogramMetric,
    MetricsRegistry,
    SummaryMetric,
)
from src.infrastructure.observability.structured_logging import (
    ConsoleFormatter,
    JSONFormatter,
    PipelineLogger,
    TimedLogContext,
    generate_correlation_id,
    get_job_id,
    get_request_id,
    get_span_id,
    get_trace_id,
    get_user_id,
    redact_sensitive_data,
    set_job_id,
    set_request_id,
    set_span_id,
    set_trace_id,
    set_user_id,
)
from src.infrastructure.observability.tracing import (
    InMemoryExporter,
    OTLPExporter,
    SamplingDecision,
    Span,
    SpanStatus,
    Tracer,
)



class TestTracer(unittest.TestCase):
    def test_start_span_context_manager(self) -> None:
        tracer = Tracer(service_name="test")
        with tracer.start_span("root") as span:
            assert span.name == "root"
            assert span.trace_id is not None
        assert span.end_time is not None

    def test_nested_spans(self) -> None:
        tracer = Tracer(service_name="test")
        with tracer.start_span("parent") as parent:
            with tracer.start_span("child") as child:
                assert child.parent_span_id == parent.span_id
        assert parent.end_time is not None
        assert child.end_time is not None

    def test_create_span(self) -> None:
        tracer = Tracer(service_name="test")
        span = tracer.create_span(name="manual")
        assert span.name == "manual"
        assert span.end_time is None

    def test_get_spans(self) -> None:
        tracer = Tracer(service_name="test")
        with tracer.start_span("s1", force_sample=True):
            pass
        spans = tracer.get_all_spans()
        assert len(spans) == 1

    def test_get_traces(self) -> None:
        tracer = Tracer(service_name="test")
        with tracer.start_span("s1", force_sample=True):
            pass
        traces = set(s.trace_id for s in tracer.get_all_spans())
        assert len(traces) >= 1

    def test_clear(self) -> None:
        tracer = Tracer(service_name="test")
        with tracer.start_span("s1", force_sample=True):
            pass
        tracer.clear()
        assert tracer.get_all_spans() == []

    def test_inject_context(self) -> None:
        tracer = Tracer(service_name="test")
        span = Span(name="test", trace_id="t1", span_id="s1")
        headers = tracer.inject_context(span)
        assert "traceparent" in headers

    def test_extract_context(self) -> None:
        tracer = Tracer(service_name="test")
        trace_id, parent_id, sampled = tracer.extract_context({"traceparent": "00-abc-def-01"})
        assert trace_id == "abc"
        assert parent_id == "def"

    def test_extract_context_empty(self) -> None:
        tracer = Tracer(service_name="test")
        trace_id, parent_id, sampled = tracer.extract_context({})
        assert trace_id is not None
        assert parent_id is None

    def test_get_stats(self) -> None:
        tracer = Tracer(service_name="test")
        with tracer.start_span("s1"):
            pass
        stats = tracer.get_stats()
        assert "total_spans" in stats
        assert "trace_count" in stats

    def test_span_error_records_exception(self) -> None:
        tracer = Tracer(service_name="test")
        with pytest.raises(ValueError):
            with tracer.start_span("failing", force_sample=True):
                raise ValueError("test error")
        spans = tracer.get_all_spans()
        assert len(spans) == 1
        assert spans[0].status == SpanStatus.ERROR
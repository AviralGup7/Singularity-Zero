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



class TestMetricsRegistry(unittest.TestCase):
    def test_counter_factory(self) -> None:
        r = MetricsRegistry(prefix="test")
        c = r.counter("requests")
        c.inc()
        assert c.get() == 1.0

    def test_gauge_factory(self) -> None:
        r = MetricsRegistry(prefix="test")
        g = r.gauge("connections")
        g.set(10.0)
        assert g.get() == 10.0

    def test_histogram_factory(self) -> None:
        r = MetricsRegistry(prefix="test")
        h = r.histogram("latency")
        h.observe(0.5)
        assert h.get()["count"] == 1

    def test_summary_factory(self) -> None:
        r = MetricsRegistry(prefix="test")
        s = r.summary("error_rate")
        s.observe(0.05)
        assert s.get()["count"] == 1

    def test_expose_prometheus(self) -> None:
        r = MetricsRegistry(prefix="test")
        r.counter("total").inc()
        output = r.expose_prometheus()
        assert "# HELP test_total" in output
        assert "# TYPE test_total counter" in output

    def test_get_all(self) -> None:
        r = MetricsRegistry(prefix="test")
        r.counter("c1").inc()
        all_metrics = r.get_all()
        assert "counters" in all_metrics
        assert "timestamp" in all_metrics

    def test_reset(self) -> None:
        r = MetricsRegistry(prefix="test")
        r.counter("c1").inc(5.0)
        r.reset()
        assert r.counter("c1").get() == 0.0
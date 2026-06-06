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



class TestFormatLabels(unittest.TestCase):
    def test_empty(self) -> None:
        r = MetricsRegistry(prefix="test")
        output = r.expose_prometheus()
        assert isinstance(output, str)

    def test_single(self) -> None:
        r = MetricsRegistry(prefix="test")
        r.counter("requests", labels={"job": "scan"}).inc()
        output = r.expose_prometheus()
        assert 'job="scan"' in output

    def test_multiple_sorted(self) -> None:
        r = MetricsRegistry(prefix="test")
        r.counter("requests", labels={"b": "2", "a": "1"}).inc()
        output = r.expose_prometheus()
        assert 'a="1"' in output
        assert 'b="2"' in output
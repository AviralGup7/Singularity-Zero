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



class TestSummaryMetric(unittest.TestCase):
    def test_observe(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            s.observe(v)
        data = s.get()
        assert data["count"] == 5
        assert data["mean"] == 3.0
        assert data["min"] == 1.0
        assert data["max"] == 5.0

    def test_empty_summary(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        data = s.get()
        assert data["count"] == 0

    def test_max_samples(self) -> None:
        s = SummaryMetric(name="test", description="test summary", max_samples=5)
        for i in range(10):
            s.observe(float(i))
        data = s.get()
        assert data["count"] <= 5
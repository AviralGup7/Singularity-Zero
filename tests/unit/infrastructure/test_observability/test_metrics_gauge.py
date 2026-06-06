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



class TestGaugeMetric(unittest.TestCase):
    def test_set(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(42.0)
        assert g.get() == 42.0

    def test_inc(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(10.0)
        g.inc(5.0)
        assert g.get() == 15.0

    def test_dec(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(10.0)
        g.dec(3.0)
        assert g.get() == 7.0

    def test_track_inprogress(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(0.0)
        with g.track_inprogress():
            assert g.get() == 1.0
        assert g.get() == 0.0
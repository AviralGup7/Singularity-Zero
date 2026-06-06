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



class TestSamplingStrategy(unittest.TestCase):
    def test_always_on(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.ALWAYS_ON)
        assert sd.should_sample("abc123") is True

    def test_always_off(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.ALWAYS_OFF)
        assert sd.should_sample("abc123") is False

    def test_probabilistic_rate_1(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.PROBABILISTIC, rate=1.0)
        assert sd.should_sample("0000000000000000") is True

    def test_probabilistic_rate_0(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.PROBABILISTIC, rate=0.0)
        assert sd.should_sample("ffffffffffffffff") is False

    def test_should_sample_error(self) -> None:
        sd = SamplingDecision()
        assert sd.should_sample_error() is True
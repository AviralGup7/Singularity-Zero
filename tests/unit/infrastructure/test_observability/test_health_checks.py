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



class TestHealthChecker(unittest.TestCase):
    def test_register_and_get_component(self) -> None:
        checker = HealthChecker()

        async def healthy_check() -> ComponentHealth:
            return ComponentHealth(name="test", status=ComponentStatus.UP)

        checker.register("test", healthy_check)
        component = checker.get_component("test")
        assert component is not None
        assert component.name == "test"

    def test_unregister(self) -> None:
        checker = HealthChecker()

        async def dummy_check() -> ComponentHealth:
            return ComponentHealth(name="test")

        checker.register("test", dummy_check)
        checker.unregister("test")
        assert checker.get_component("test") is None

    def test_check_component_no_handler(self) -> None:
        checker = HealthChecker()
        result = asyncio.run(checker.check_component("missing"))
        assert result.status == ComponentStatus.UNKNOWN

    def test_check_all_empty(self) -> None:
        checker = HealthChecker()
        result = asyncio.run(checker.check_all())
        assert result.overall_status == HealthStatus.HEALTHY

    def test_get_history_empty(self) -> None:
        checker = HealthChecker()
        assert checker.get_history() == []

    def test_get_trend_empty(self) -> None:
        checker = HealthChecker()
        trend = checker.get_trend()
        assert trend["trend"] == "unknown"

    def test_get_last_result_none(self) -> None:
        checker = HealthChecker()
        assert checker.get_last_result() is None

    def test_get_summary(self) -> None:
        checker = HealthChecker()
        summary = checker.get_summary()
        assert "overall_status" in summary
        assert "component_count" in summary

    def test_health_check_result_to_dict(self) -> None:
        result = HealthCheckResult(
            overall_status=HealthStatus.HEALTHY,
            version="1.0.0",
            duration_ms=10.5,
        )
        d = result.to_dict()
        assert d["overall_status"] == "healthy"
        assert d["version"] == "1.0.0"

    def test_health_check_result_to_json(self) -> None:
        result = HealthCheckResult(overall_status=HealthStatus.HEALTHY)
        json_str = result.to_json()
        assert "healthy" in json_str

    def test_component_health_to_dict(self) -> None:
        health = ComponentHealth(name="redis", status=ComponentStatus.UP, message="ok")
        d = health.to_dict()
        assert d["name"] == "redis"
        assert d["status"] == "up"
        assert d["message"] == "ok"
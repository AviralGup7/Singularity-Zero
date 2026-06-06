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



class TestStructuredLogging(unittest.TestCase):
    def test_generate_correlation_id(self) -> None:
        cid = generate_correlation_id()
        assert len(cid) == 16

    def test_context_vars(self) -> None:
        set_trace_id("t1")
        set_span_id("s1")
        set_request_id("r1")
        set_job_id("j1")
        set_user_id("u1")
        assert get_trace_id() == "t1"
        assert get_span_id() == "s1"
        assert get_request_id() == "r1"
        assert get_job_id() == "j1"
        assert get_user_id() == "u1"

    def test_redact_sensitive_fields(self) -> None:
        data = {"password": "secret123", "username": "admin"}
        redacted = redact_sensitive_data(data)
        assert redacted["password"] == "[REDACTED]"
        assert redacted["username"] == "admin"

    def test_redact_nested_dict(self) -> None:
        data = {"auth": {"token": "abc123"}}
        redacted = redact_sensitive_data(data)
        assert redacted["auth"]["token"] == "[REDACTED]"

    def test_redact_list(self) -> None:
        data = [{"password": "secret"}, {"safe": "value"}]
        redacted = redact_sensitive_data(data)
        assert redacted[0]["password"] == "[REDACTED]"
        assert redacted[1]["safe"] == "value"

    def test_redact_non_dict(self) -> None:
        assert redact_sensitive_data(42) == 42
        assert redact_sensitive_data("hello") == "hello"

    def test_json_formatter(self) -> None:
        import logging

        formatter = JSONFormatter(service_name="test")
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        import json

        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "test message"
        assert data["service"] == "test"

    def test_console_formatter(self) -> None:
        import logging

        formatter = ConsoleFormatter(service_name="test")
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "test message" in output

    def test_pipeline_logger(self) -> None:
        logger = PipelineLogger("test_pkg")
        assert logger.name == "test_pkg"
        assert logger.logger is not None

    def test_timed_log_context(self) -> None:
        logger = PipelineLogger("test_pkg")
        ctx = TimedLogContext(logger, "test_op", target="example.com")
        ctx.__enter__()
        import time

        time.sleep(0.01)
        ctx.__exit__(None, None, None)
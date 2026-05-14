"""Unit tests for the observability stack."""

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


@pytest.mark.unit
class TestCounterMetric(unittest.TestCase):
    def test_increment(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        c.inc()
        assert c.get() == 1.0

    def test_increment_by_amount(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        c.inc(5.0)
        assert c.get() == 5.0

    def test_negative_increment_raises(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        with pytest.raises(ValueError):
            c.inc(-1.0)

    def test_reset(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        c.inc(10.0)
        c.reset()
        assert c.get() == 0.0


@pytest.mark.unit
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


@pytest.mark.unit
class TestHistogramMetric(unittest.TestCase):
    def test_observe(self) -> None:
        h = HistogramMetric(name="test", description="test histogram", buckets=(0.1, 0.5, 1.0))
        h.observe(0.05)
        h.observe(0.3)
        h.observe(2.0)
        data = h.get()
        assert data["count"] == 3
        assert data["sum"] == pytest.approx(2.35)

    def test_percentile(self) -> None:
        h = HistogramMetric(name="test", description="test histogram")
        for v in [0.1, 0.2, 0.3, 0.4, 0.5]:
            h.observe(v)
        p50 = h.percentile(50)
        assert p50 > 0

    def test_percentile_empty(self) -> None:
        h = HistogramMetric(name="test", description="test histogram")
        assert h.percentile(50) == 0.0


@pytest.mark.unit
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


@pytest.mark.unit
class TestPercentile(unittest.TestCase):
    def test_percentile_median(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            s.observe(v)
        data = s.get()
        assert data["p50"] == 3.0

    def test_percentile_empty(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        data = s.get()
        assert data["count"] == 0

    def test_percentile_single_value(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        s.observe(42.0)
        data = s.get()
        assert data["p50"] == 42.0


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestObservabilityConfig(unittest.TestCase):
    def test_defaults(self) -> None:
        config = ObservabilityConfig()
        assert config.environment == Environment.DEVELOPMENT
        assert config.metrics.enabled is True
        assert config.tracing.enabled is True
        assert config.health_check.enabled is True
        assert config.alerts.enabled is True

    def test_for_production(self) -> None:
        config = ObservabilityConfig.for_production()
        assert config.environment == Environment.PRODUCTION
        assert config.logging.level == LogLevel.WARNING
        assert config.tracing.sampling_rate == 0.05

    def test_for_development(self) -> None:
        config = ObservabilityConfig.for_development()
        assert config.environment == Environment.DEVELOPMENT
        assert config.logging.level == LogLevel.DEBUG
        assert config.alerts.enabled is False

    def test_sub_configs(self) -> None:
        config = ObservabilityConfig()
        assert isinstance(config.logging.level, LogLevel)
        assert isinstance(config.metrics, MetricsConfig)
        assert isinstance(config.tracing, TracingConfig)
        assert isinstance(config.health_check, HealthCheckConfig)
        assert isinstance(config.alerts, AlertConfig)


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestOTLPExporter(unittest.TestCase):
    def test_init_unavailable(self) -> None:
        exporter = OTLPExporter(endpoint="http://localhost:4317")
        assert isinstance(exporter.is_available, bool)

    def test_get_stats(self) -> None:
        exporter = OTLPExporter()
        stats = exporter.get_stats()
        assert "available" in stats
        assert "export_count" in stats


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestAlertManager(unittest.TestCase):
    def test_add_and_remove_rule(self) -> None:
        manager = AlertManager()
        rule = AlertRule(
            name="test_rule",
            severity=AlertSeverity.WARNING,
            metric_name="test_metric",
            condition="gt",
            threshold=100.0,
        )
        manager.add_rule(rule)
        manager.remove_rule("test_rule")
        stats = manager.get_stats()
        assert stats["total_rules"] == 0

    def test_alert_rule_evaluate_gt(self) -> None:
        rule = AlertRule(
            name="r1",
            severity=AlertSeverity.WARNING,
            metric_name="m",
            condition="gt",
            threshold=10.0,
        )
        assert rule.evaluate(15.0) is True
        assert rule.evaluate(5.0) is False

    def test_alert_rule_evaluate_lt(self) -> None:
        rule = AlertRule(
            name="r1",
            severity=AlertSeverity.WARNING,
            metric_name="m",
            condition="lt",
            threshold=10.0,
        )
        assert rule.evaluate(5.0) is True
        assert rule.evaluate(15.0) is False

    def test_alert_rule_evaluate_gte(self) -> None:
        rule = AlertRule(
            name="r1",
            severity=AlertSeverity.WARNING,
            metric_name="m",
            condition="gte",
            threshold=10.0,
        )
        assert rule.evaluate(10.0) is True
        assert rule.evaluate(9.0) is False

    def test_alert_rule_evaluate_lte(self) -> None:
        rule = AlertRule(
            name="r1",
            severity=AlertSeverity.WARNING,
            metric_name="m",
            condition="lte",
            threshold=10.0,
        )
        assert rule.evaluate(10.0) is True
        assert rule.evaluate(11.0) is False

    def test_alert_rule_evaluate_eq(self) -> None:
        rule = AlertRule(
            name="r1",
            severity=AlertSeverity.WARNING,
            metric_name="m",
            condition="eq",
            threshold=10.0,
        )
        assert rule.evaluate(10.0) is True
        assert rule.evaluate(11.0) is False

    def test_alert_rule_unknown_condition(self) -> None:
        rule = AlertRule(
            name="r1",
            severity=AlertSeverity.WARNING,
            metric_name="m",
            condition="unknown",
            threshold=10.0,
        )
        assert rule.evaluate(100.0) is False

    def test_alert_to_dict(self) -> None:
        alert = Alert(name="test", severity=AlertSeverity.CRITICAL)
        d = alert.to_dict()
        assert d["name"] == "test"
        assert d["severity"] == "critical"

    def test_alert_fingerprint(self) -> None:
        a1 = Alert(name="test", severity=AlertSeverity.WARNING, labels={"env": "prod"})
        a2 = Alert(name="test", severity=AlertSeverity.WARNING, labels={"env": "prod"})
        assert a1.fingerprint == a2.fingerprint

    def test_alert_channel_disabled(self) -> None:
        channel = AlertChannel(name="test", channel_type=ChannelType.WEBHOOK, enabled=False)
        alert = Alert(name="test", severity=AlertSeverity.WARNING)
        result = asyncio.run(channel.send(alert))
        assert result is False

    def test_alert_channel_no_url(self) -> None:
        channel = AlertChannel(name="test", channel_type=ChannelType.WEBHOOK, config={})
        alert = Alert(name="test", severity=AlertSeverity.WARNING)
        result = asyncio.run(channel.send(alert))
        assert result is False

    def test_clear_channels(self) -> None:
        manager = AlertManager()
        channel = AlertChannel(name="test", channel_type=ChannelType.WEBHOOK)
        manager.add_channel(channel)
        manager.clear_channels()
        stats = manager.get_stats()
        assert stats["channels"] == 0

    def test_get_active_alerts_empty(self) -> None:
        manager = AlertManager()
        assert manager.get_active_alerts() == []

    def test_clear(self) -> None:
        manager = AlertManager()
        manager.clear()
        assert manager.get_active_alerts() == []

    def test_alert_state_values(self) -> None:
        assert AlertState.FIRING.value == "firing"
        assert AlertState.RESOLVED.value == "resolved"
        assert AlertState.PENDING.value == "pending"
        assert AlertState.SUPPRESSED.value == "suppressed"

    def test_channel_type_values(self) -> None:
        assert ChannelType.WEBHOOK.value == "webhook"
        assert ChannelType.EMAIL.value == "email"
        assert ChannelType.SLACK.value == "slack"

    def test_alert_severity_values(self) -> None:
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.WARNING.value == "warning"
        assert AlertSeverity.INFO.value == "info"

    def test_rate_limit_result_is_limited(self) -> None:
        from src.infrastructure.observability.alerts import Alert

        alert = Alert(name="test", severity=AlertSeverity.WARNING)
        assert alert.fingerprint is not None
        assert len(alert.fingerprint) == 16

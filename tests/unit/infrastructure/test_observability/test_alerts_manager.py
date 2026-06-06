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
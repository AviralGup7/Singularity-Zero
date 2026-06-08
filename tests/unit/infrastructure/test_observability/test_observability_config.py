import unittest

from src.infrastructure.observability.config import (
    AlertConfig,
    Environment,
    HealthCheckConfig,
    LogLevel,
    MetricsConfig,
    ObservabilityConfig,
    TracingConfig,
)


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

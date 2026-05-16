"""Observability configuration for the cyber security test pipeline.

Provides centralized configuration for logging, metrics, tracing,
health checks, and alerting with environment variable support
and YAML file loading.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum


class Environment(StrEnum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    """Log severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SamplingStrategy(StrEnum):
    """Trace sampling strategies."""

    ALWAYS_ON = "always_on"
    ALWAYS_OFF = "always_off"
    PROBABILISTIC = "probabilistic"
    RATE_LIMITING = "rate_limiting"


@dataclass
class LoggingConfig:
    """Configuration for structured logging.

    Attributes:
        level: Minimum log level to emit.
        format: Output format (json or console).
        output_path: File path for log output. None for stdout.
        max_file_size_mb: Maximum size of a single log file before rotation.
        backup_count: Number of rotated log files to retain.
        retention_days: Days to keep log files before deletion.
        enable_async: Whether to use async log handlers.
        enable_correlation: Whether to add trace_id/request_id to all logs.
        sensitive_fields: Field names to redact in log output.
        include_source: Whether to include source file and line number.
        service_name: Name of the service for log identification.
        extra_context: Additional context to include in all log entries.
    """

    level: LogLevel = LogLevel.INFO
    format: str = "json"
    output_path: str | None = None
    max_file_size_mb: int = 100
    backup_count: int = 10
    retention_days: int = 30
    enable_async: bool = True
    enable_correlation: bool = True
    sensitive_fields: list[str] = field(
        default_factory=lambda: [
            "password",
            "token",
            "api_key",
            "secret",
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "access_token",
            "refresh_token",
            "private_key",
            "credentials",
        ]
    )
    include_source: bool = False
    service_name: str = "cyber-security-pipeline"
    extra_context: dict[str, str] = field(default_factory=dict)


@dataclass
class MetricsConfig:
    """Configuration for metrics collection.

    Attributes:
        enabled: Whether metrics collection is active.
        prefix: Prefix for all metric names.
        export_interval_seconds: Interval between metric exports.
        enable_prometheus: Whether to expose Prometheus metrics endpoint.
        prometheus_port: Port for Prometheus metrics scraping.
        prometheus_host: Host for Prometheus metrics endpoint.
        enable_histogram: Whether to collect histogram metrics.
        histogram_buckets: Bucket boundaries for histogram metrics.
        max_data_points: Maximum number of unique metric data points.
        aggregation_interval_seconds: Interval for aggregating metrics across workers.
    """

    enabled: bool = True
    prefix: str = "cyber_pipeline"
    export_interval_seconds: float = 15.0
    enable_prometheus: bool = True
    prometheus_port: int = 9090
    prometheus_host: str = "0.0.0.0" # noqa: S104 # noqa: S104
    enable_histogram: bool = True
    histogram_buckets: tuple[float, ...] = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.075,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        7.5,
        10.0,
        30.0,
        60.0,
    )
    max_data_points: int = 10000
    aggregation_interval_seconds: float = 60.0


@dataclass
class TracingConfig:
    """Configuration for distributed tracing.

    Attributes:
        enabled: Whether tracing is active.
        service_name: Service name for trace identification.
        sampling_strategy: Strategy for sampling traces.
        sampling_rate: Probability of sampling (0.0 to 1.0) for probabilistic strategy.
        max_attributes_per_span: Maximum number of attributes per span.
        max_events_per_span: Maximum number of events per span.
        max_links_per_span: Maximum number of links per span.
        max_trace_length: Maximum number of spans per trace.
        exporter_type: Exporter backend (memory or otlp).
        otlp_endpoint: OTLP collector endpoint URL.
        otlp_insecure: Whether to use insecure gRPC for OTLP.
        otlp_headers: Additional headers for OTLP exporter.
        propagate_context: Whether to propagate trace context across services.
        include_code_attributes: Whether to include code file/line attributes.
        max_traces_in_memory: Maximum number of traces to retain in memory exporter.
    """

    enabled: bool = True
    service_name: str = "cyber-security-pipeline"
    sampling_strategy: SamplingStrategy = SamplingStrategy.PROBABILISTIC
    sampling_rate: float = 0.1
    max_attributes_per_span: int = 128
    max_events_per_span: int = 128
    max_links_per_span: int = 128
    max_trace_length: int = 10000
    exporter_type: str = "memory"
    otlp_endpoint: str = "http://localhost:4317"
    otlp_insecure: bool = True
    otlp_headers: dict[str, str] = field(default_factory=dict)
    propagate_context: bool = True
    include_code_attributes: bool = False
    max_traces_in_memory: int = 1000


@dataclass
class HealthCheckConfig:
    """Configuration for health checks.

    Attributes:
        enabled: Whether health checks are active.
        check_interval_seconds: Interval between periodic health checks.
        history_size: Number of historical health check results to retain.
        timeout_seconds: Timeout for individual health check probes.
        failure_threshold: Consecutive failures before marking component unhealthy.
        components: List of component names to check.
    """

    enabled: bool = True
    check_interval_seconds: float = 30.0
    history_size: int = 100
    timeout_seconds: float = 5.0
    failure_threshold: int = 3
    components: list[str] = field(
        default_factory=lambda: [
            "redis",
            "sqlite",
            "workers",
            "cache",
            "queue",
            "api",
            "websocket",
        ]
    )


@dataclass
class AlertConfig:
    """Configuration for alerting.

    Attributes:
        enabled: Whether alerting is active.
        evaluation_interval_seconds: Interval between alert evaluations.
        deduplication_window_seconds: Window for deduplicating identical alerts.
        suppression_window_seconds: Window for suppressing repeated alerts.
        min_alert_severity: Minimum severity level to trigger alerts.
        channels: Alert notification channel configurations.
    """

    enabled: bool = True
    evaluation_interval_seconds: float = 30.0
    deduplication_window_seconds: float = 300.0
    suppression_window_seconds: float = 900.0
    min_alert_severity: str = "warning"
    channels: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ObservabilityConfig:
    """Top-level observability configuration.

    Aggregates all subsystem configurations and provides environment-aware
    defaults for development, staging, and production deployments.

    Attributes:
        environment: Deployment environment.
        logging: Logging subsystem configuration.
        metrics: Metrics subsystem configuration.
        tracing: Tracing subsystem configuration.
        health_check: Health check subsystem configuration.
        alerts: Alerting subsystem configuration.
    """

    environment: Environment = Environment.DEVELOPMENT
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    tracing: TracingConfig = field(default_factory=TracingConfig)
    health_check: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)

    @classmethod
    def from_env(cls) -> ObservabilityConfig:
        """Create configuration from environment variables.

        Environment variables:
            OBSERVABILITY_ENV: Environment (development/staging/production).
            OBSERVABILITY_LOG_LEVEL: Log level string.
            OBSERVABILITY_LOG_FORMAT: Log format (json/console).
            OBSERVABILITY_LOG_OUTPUT: Log file path.
            OBSERVABILITY_METRICS_ENABLED: Enable metrics (true/false).
            OBSERVABILITY_METRICS_PORT: Prometheus metrics port.
            OBSERVABILITY_TRACING_ENABLED: Enable tracing (true/false).
            OBSERVABILITY_TRACING_ENDPOINT: OTLP endpoint URL.
            OBSERVABILITY_SAMPLING_RATE: Trace sampling rate (0.0-1.0).
            OBSERVABILITY_HEALTH_CHECK_INTERVAL: Health check interval seconds.
            OBSERVABILITY_ALERTS_ENABLED: Enable alerts (true/false).

        Returns:
            ObservabilityConfig populated from environment.
        """
        env_str = os.getenv("OBSERVABILITY_ENV", "development").lower()
        environment = (
            Environment(env_str)
            if env_str in [e.value for e in Environment]
            else Environment.DEVELOPMENT
        )

        log_level_str = os.getenv("OBSERVABILITY_LOG_LEVEL", "INFO").upper()
        log_level = (
            LogLevel(log_level_str)
            if log_level_str in [level.value for level in LogLevel]
            else LogLevel.INFO
        )

        config = cls(
            environment=environment,
            logging=LoggingConfig(
                level=log_level,
                format=os.getenv("OBSERVABILITY_LOG_FORMAT", "json"),
                output_path=os.getenv("OBSERVABILITY_LOG_OUTPUT") or None,
            ),
            metrics=MetricsConfig(
                enabled=os.getenv("OBSERVABILITY_METRICS_ENABLED", "true").lower() == "true",
                prometheus_port=int(os.getenv("OBSERVABILITY_METRICS_PORT", "9090")),
            ),
            tracing=TracingConfig(
                enabled=os.getenv("OBSERVABILITY_TRACING_ENABLED", "true").lower() == "true",
                otlp_endpoint=os.getenv("OBSERVABILITY_TRACING_ENDPOINT", "http://localhost:4317"),
                sampling_rate=float(os.getenv("OBSERVABILITY_SAMPLING_RATE", "0.1")),
            ),
            health_check=HealthCheckConfig(
                check_interval_seconds=float(
                    os.getenv("OBSERVABILITY_HEALTH_CHECK_INTERVAL", "30")
                ),
            ),
            alerts=AlertConfig(
                enabled=os.getenv("OBSERVABILITY_ALERTS_ENABLED", "true").lower() == "true",
            ),
        )

        if environment == Environment.PRODUCTION:
            config.logging.level = LogLevel.WARNING
            config.logging.enable_async = True
            config.tracing.sampling_strategy = SamplingStrategy.PROBABILISTIC
            config.tracing.sampling_rate = 0.05
            config.tracing.exporter_type = "otlp"
            config.metrics.export_interval_seconds = 10.0
            config.alerts.evaluation_interval_seconds = 15.0
        elif environment == Environment.STAGING:
            config.tracing.sampling_rate = 0.2
            config.tracing.exporter_type = "otlp"
            config.metrics.export_interval_seconds = 15.0
        else:
            config.logging.level = LogLevel.DEBUG
            config.logging.format = "console"
            config.tracing.sampling_strategy = SamplingStrategy.ALWAYS_ON
            config.tracing.exporter_type = "memory"
            config.metrics.export_interval_seconds = 5.0

        return config

    @classmethod
    def for_production(cls) -> ObservabilityConfig:
        """Create a production-optimized configuration.

        Returns:
            ObservabilityConfig tuned for production workloads.
        """
        config = cls(environment=Environment.PRODUCTION)
        config.logging.level = LogLevel.WARNING
        config.logging.enable_async = True
        config.logging.max_file_size_mb = 500
        config.logging.backup_count = 30
        config.logging.retention_days = 90
        config.metrics.export_interval_seconds = 10.0
        config.metrics.enable_prometheus = True
        config.tracing.enabled = True
        config.tracing.sampling_strategy = SamplingStrategy.PROBABILISTIC
        config.tracing.sampling_rate = 0.05
        config.tracing.exporter_type = "otlp"
        config.health_check.check_interval_seconds = 15.0
        config.alerts.evaluation_interval_seconds = 15.0
        return config

    @classmethod
    def for_development(cls) -> ObservabilityConfig:
        """Create a development-friendly configuration.

        Returns:
            ObservabilityConfig tuned for local development.
        """
        config = cls(environment=Environment.DEVELOPMENT)
        config.logging.level = LogLevel.DEBUG
        config.logging.format = "console"
        config.logging.include_source = True
        config.tracing.sampling_strategy = SamplingStrategy.ALWAYS_ON
        config.tracing.exporter_type = "memory"
        config.metrics.export_interval_seconds = 5.0
        config.health_check.check_interval_seconds = 10.0
        config.alerts.enabled = False
        return config


_config: ObservabilityConfig | None = None


def get_config() -> ObservabilityConfig:
    """Get the global observability configuration.

    Returns a cached instance if one exists, otherwise creates one
    from environment variables.

    Returns:
        The global ObservabilityConfig instance.
    """
    global _config
    if _config is None:
        _config = ObservabilityConfig.from_env()
    return _config


def set_config(config: ObservabilityConfig) -> None:
    """Set the global observability configuration.

    Args:
        config: The configuration to use globally.
    """
    global _config
    _config = config

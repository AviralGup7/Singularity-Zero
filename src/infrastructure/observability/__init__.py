"""Comprehensive observability stack for the cyber security test pipeline.

Provides structured logging, metrics collection, distributed tracing,
health checks, and alerting across all pipeline components.

Packages integrated:
    - queue_system: Job queue metrics, worker health, queue depth monitoring
    - execution_engine: Execution duration, concurrency metrics, task tracing
    - cache_layer: Cache hit/miss rates, backend health, eviction tracking
    - fastapi_dashboard: Request latency, error rates, endpoint metrics
    - websocket_server: Connection counts, message throughput, heartbeat health
    - optimized_stages: Stage duration, memory usage, rate limiter metrics

Usage:
    from src.infrastructure.observability import get_logger, metrics, tracer, health, alerts

    logger = get_logger("queue_system")
    logger.info("Job enqueued", job_id="abc123", target="example.com")

    metrics.counter("jobs_enqueued").inc()
    metrics.histogram("job_duration").observe(duration_ms)

    with tracer.start_span("process_job") as span:
        span.set_attribute("job_id", "abc123")
        # ... job processing ...

    status = await health.check_all()
    await alerts.evaluate()
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "1.0.0"

_EXPORTS: dict[str, str] = {
    "ObservabilityConfig": "src.infrastructure.observability.config",
    "get_config": "src.infrastructure.observability.config",
    "get_logger": "src.infrastructure.observability.structured_logging",
    "setup_logging": "src.infrastructure.observability.structured_logging",
    "PipelineLogger": "src.infrastructure.observability.structured_logging",
    "redact_sensitive_data": "src.infrastructure.observability.structured_logging",
    "MetricsRegistry": "src.infrastructure.observability.metrics",
    "get_metrics": "src.infrastructure.observability.metrics",
    "Tracer": "src.infrastructure.observability.tracing",
    "get_tracer": "src.infrastructure.observability.tracing",
    "HealthChecker": "src.infrastructure.observability.health_checks",
    "get_health_checker": "src.infrastructure.observability.health_checks",
    "AlertManager": "src.infrastructure.observability.alerts",
    "get_alert_manager": "src.infrastructure.observability.alerts",
}

__all__ = [
    "AlertManager",
    "get_alert_manager",
    "get_config",
    "get_health_checker",
    "get_logger",
    "get_metrics",
    "get_tracer",
    "HealthChecker",
    "MetricsRegistry",
    "ObservabilityConfig",
    "PipelineLogger",
    "redact_sensitive_data",
    "setup_logging",
    "Tracer",
]


def __getattr__(name: str) -> Any:
    module_path = _EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_path)
    value = getattr(module, name)
    globals()[name] = value
    return value

"""Prometheus metrics for the recon collectors.

Helpers increment provider-level counters and observe durations through
the internal MetricsRegistry so names are ``cyber_pipeline_recon_*``.
If the registry cannot be constructed, calls are no-ops.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _counter(name: str, description: str, labels: dict[str, str]) -> Any | None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        return get_metrics().counter(name, description, labels=labels)
    except Exception:
        logger.debug("Recon metric counter failed for %s", name, exc_info=True)
        return None


def _histogram(name: str, description: str, labels: dict[str, str]) -> Any | None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        return get_metrics().histogram(name, description, labels=labels)
    except Exception:
        logger.debug("Recon metric histogram failed for %s", name, exc_info=True)
        return None


def increment_requests(provider: str, n: int = 1) -> None:
    metric = _counter(
        "recon_provider_requests_total",
        "Total requests made to a provider",
        {"provider": provider},
    )
    if metric is not None:
        metric.inc(n)


def increment_errors(provider: str, n: int = 1) -> None:
    metric = _counter(
        "recon_provider_errors_total",
        "Total errors encountered by a provider",
        {"provider": provider},
    )
    if metric is not None:
        metric.inc(n)


def increment_urls(provider: str, n: int = 1) -> None:
    metric = _counter(
        "recon_provider_urls_total",
        "Number of URLs emitted by a provider",
        {"provider": provider},
    )
    if metric is not None:
        metric.inc(n)


def observe_duration(provider: str, seconds: float) -> None:
    metric = _histogram(
        "recon_provider_duration_seconds",
        "Duration in seconds of provider collection calls",
        {"provider": provider},
    )
    if metric is not None:
        metric.observe(seconds)


__all__ = [
    "increment_requests",
    "increment_errors",
    "increment_urls",
    "observe_duration",
]

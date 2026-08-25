"""WebSocket metrics via the internal MetricsRegistry (cyber_pipeline_ prefix)."""

from __future__ import annotations

import logging
from typing import Any

from src.infrastructure.observability.cardinality import BoundedLabelSet

logger = logging.getLogger(__name__)

WS_USER_IDS = BoundedLabelSet(max_size=256, fallback="__other__", name="ws_user_ids")
WS_JOB_IDS = BoundedLabelSet(max_size=128, fallback="__other__", name="ws_job_ids")


class RegistryBackedMetric:
    """prometheus_client-shaped facade over ``get_metrics()``.

    Call sites keep ``.labels(...).inc()`` / ``.observe()`` / ``.dec()``.
    Series land in MetricsRegistry as ``cyber_pipeline_<name>``.
    """

    def __init__(
        self,
        kind: str,
        name: str,
        documentation: str,
        labelnames: tuple[str, ...] = (),
        labels: dict[str, str] | None = None,
    ) -> None:
        self._kind = kind
        self._name = name
        self._documentation = documentation
        self._labelnames = labelnames
        self._labels = dict(labels or {})

    def labels(self, *args: Any, **kwargs: Any) -> RegistryBackedMetric:
        bound: dict[str, str] = dict(self._labels)
        if args:
            for key, value in zip(self._labelnames, args, strict=False):
                bound[str(key)] = str(value)
        bound.update({str(k): str(v) for k, v in kwargs.items()})
        return RegistryBackedMetric(
            self._kind, self._name, self._documentation, self._labelnames, bound
        )

    def _target(self) -> Any:
        from src.infrastructure.observability.metrics import get_metrics

        registry = get_metrics()
        if self._kind == "counter":
            return registry.counter(self._name, self._documentation, labels=self._labels)
        if self._kind == "gauge":
            return registry.gauge(self._name, self._documentation, labels=self._labels)
        return registry.histogram(self._name, self._documentation, labels=self._labels)

    def inc(self, amount: float = 1.0) -> None:
        try:
            self._target().inc(amount)
        except Exception:
            logger.debug("WS metric inc failed for %s", self._name, exc_info=True)

    def dec(self, amount: float = 1.0) -> None:
        try:
            self._target().dec(amount)
        except Exception:
            logger.debug("WS metric dec failed for %s", self._name, exc_info=True)

    def set(self, value: float) -> None:
        try:
            self._target().set(value)
        except Exception:
            logger.debug("WS metric set failed for %s", self._name, exc_info=True)

    def observe(self, value: float) -> None:
        try:
            self._target().observe(value)
        except Exception:
            logger.debug("WS metric observe failed for %s", self._name, exc_info=True)


def _metric(
    kind: str, name: str, documentation: str, labelnames: tuple[str, ...] = ()
) -> RegistryBackedMetric:
    return RegistryBackedMetric(kind, name, documentation, labelnames)


WS_CONNECTIONS = _metric("gauge", "ws_active_connections", "Active WebSocket connections")
WS_MESSAGES = _metric("counter", "ws_messages_broadcast_total", "Messages broadcast", ("scope",))
WS_LATENCY = _metric("histogram", "ws_dispatch_latency_seconds", "Message dispatch latency")
WS_RECONNECTS = _metric("counter", "ws_reconnections_total", "WebSocket reconnections", ("status",))
WS_HEARTBEATS = _metric("counter", "ws_heartbeat_timeouts_total", "WebSocket heartbeat timeouts")
WS_REDIS_FANOUT = _metric(
    "counter", "ws_redis_fanout_total", "WebSocket Redis fanout messages", ("direction",)
)
WS_DROPPED_MESSAGES = _metric(
    "counter",
    "ws_dropped_messages_total",
    "WebSocket messages dropped due to backpressure",
    ("scope",),
)
WS_BACKPRESSURE_EVENTS = _metric(
    "counter",
    "ws_backpressure_events_total",
    "WebSocket backpressure events emitted to clients",
    ("scope",),
)
WS_AUTHZ_REJECTIONS = _metric(
    "counter",
    "ws_authz_rejections_total",
    "WebSocket subscription authorization rejections",
    ("reason", "channel"),
)

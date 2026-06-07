from __future__ import annotations

from typing import Any

try:
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram
except ImportError:

    class MockMetric:
        def labels(self, *args: Any, **kwargs: Any) -> MockMetric:
            return self

        def inc(self, *args: Any, **kwargs: Any) -> None:
            pass

        def dec(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set(self, *args: Any, **kwargs: Any) -> None:
            pass

        def observe(self, *args: Any, **kwargs: Any) -> None:
            pass

        def time(self) -> Any:
            class DummyContext:
                def __enter__(self) -> None:
                    pass

                def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                    pass

            return DummyContext()

    Counter = Gauge = Histogram = lambda *args, **kwargs: MockMetric()  # type: ignore
    REGISTRY = None  # type: ignore


def _safe_metric(cls: Any, name: str, documentation: str, labelnames: Any = ()) -> Any:
    if REGISTRY is not None:
        try:
            if name in REGISTRY._names_to_collectors:
                return REGISTRY._names_to_collectors[name]
            return cls(name, documentation, labelnames)
        except Exception:  # noqa: S110
            pass
    return cls(name, documentation, labelnames)


WS_CONNECTIONS = _safe_metric(
    Gauge, "ws_active_connections", "Active WebSocket connections", ["user_id"]
)
WS_MESSAGES = _safe_metric(Counter, "ws_messages_broadcast_total", "Messages broadcast", ["scope"])
WS_LATENCY = _safe_metric(Histogram, "ws_dispatch_latency_seconds", "Message dispatch latency")
WS_RECONNECTS = _safe_metric(
    Counter, "ws_reconnections_total", "WebSocket reconnections", ["status"]
)
WS_HEARTBEATS = _safe_metric(Counter, "ws_heartbeat_timeouts_total", "WebSocket heartbeat timeouts")
WS_REDIS_FANOUT = _safe_metric(
    Counter, "ws_redis_fanout_total", "WebSocket Redis fanout messages", ["direction"]
)
WS_DROPPED_MESSAGES = _safe_metric(
    Counter,
    "ws_dropped_messages_total",
    "WebSocket messages dropped due to backpressure",
    ["scope", "job_id", "user_id"],
)
WS_BACKPRESSURE_EVENTS = _safe_metric(
    Counter,
    "ws_backpressure_events_total",
    "WebSocket backpressure events emitted to clients",
    ["scope"],
)
WS_AUTHZ_REJECTIONS = _safe_metric(
    Counter,
    "ws_authz_rejections_total",
    "WebSocket subscription authorization rejections",
    ["reason", "channel"],
)

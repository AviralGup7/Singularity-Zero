"""Prometheus metrics for WebSocket monitoring."""

try:
    from prometheus_client import Counter, Gauge, Histogram, REGISTRY
except ImportError:
    class MockMetric:
        def labels(self, *args, **kwargs): return self
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def time(self):
            class DummyContext:
                def __enter__(self): pass
                def __exit__(self, exc_type, exc_val, exc_tb): pass
            return DummyContext()
    Counter = Gauge = Histogram = lambda *args, **kwargs: MockMetric()
    REGISTRY = None


def _safe_metric(cls, name, documentation, labelnames=()):
    if REGISTRY is not None:
        try:
            if name in REGISTRY._names_to_collectors:
                return REGISTRY._names_to_collectors[name]
            return cls(name, documentation, labelnames)
        except Exception:
            pass
    return cls(name, documentation, labelnames)


WS_CONNECTIONS = _safe_metric(Gauge, 'ws_active_connections', 'Active WebSocket connections', ['user_id'])
WS_MESSAGES = _safe_metric(Counter, 'ws_messages_broadcast_total', 'Messages broadcast', ['scope'])
WS_LATENCY = _safe_metric(Histogram, 'ws_dispatch_latency_seconds', 'Message dispatch latency')
WS_RECONNECTS = _safe_metric(Counter, 'ws_reconnections_total', 'WebSocket reconnections', ['status'])
WS_HEARTBEATS = _safe_metric(Counter, 'ws_heartbeat_timeouts_total', 'WebSocket heartbeat timeouts')
WS_REDIS_FANOUT = _safe_metric(Counter, 'ws_redis_fanout_total', 'WebSocket Redis fanout messages', ['direction'])

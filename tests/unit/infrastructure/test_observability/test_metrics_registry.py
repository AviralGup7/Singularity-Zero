import unittest

from src.infrastructure.observability.metrics import (
    MetricsRegistry,
)


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

import unittest

from src.infrastructure.observability.metrics import (
    MetricsRegistry,
)


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

import unittest

from src.infrastructure.observability.metrics import (
    GaugeMetric,
)


class TestGaugeMetric(unittest.TestCase):
    def test_set(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(42.0)
        assert g.get() == 42.0

    def test_inc(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(10.0)
        g.inc(5.0)
        assert g.get() == 15.0

    def test_dec(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(10.0)
        g.dec(3.0)
        assert g.get() == 7.0

    def test_track_inprogress(self) -> None:
        g = GaugeMetric(name="test", description="test gauge")
        g.set(0.0)
        with g.track_inprogress():
            assert g.get() == 1.0
        assert g.get() == 0.0

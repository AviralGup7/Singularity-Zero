import unittest

from src.infrastructure.observability.metrics import (
    SummaryMetric,
)


class TestPercentile(unittest.TestCase):
    def test_percentile_median(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            s.observe(v)
        data = s.get()
        assert data["p50"] == 3.0

    def test_percentile_empty(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        data = s.get()
        assert data["count"] == 0

    def test_percentile_single_value(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        s.observe(42.0)
        data = s.get()
        assert data["p50"] == 42.0

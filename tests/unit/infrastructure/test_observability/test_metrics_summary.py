import unittest

from src.infrastructure.observability.metrics import (
    SummaryMetric,
)


class TestSummaryMetric(unittest.TestCase):
    def test_observe(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            s.observe(v)
        data = s.get()
        assert data["count"] == 5
        assert data["mean"] == 3.0
        assert data["min"] == 1.0
        assert data["max"] == 5.0

    def test_empty_summary(self) -> None:
        s = SummaryMetric(name="test", description="test summary")
        data = s.get()
        assert data["count"] == 0

    def test_max_samples(self) -> None:
        s = SummaryMetric(name="test", description="test summary", max_samples=5)
        for i in range(10):
            s.observe(float(i))
        data = s.get()
        assert data["count"] <= 5

import unittest

import pytest

from src.infrastructure.observability.metrics import (
    HistogramMetric,
)


class TestHistogramMetric(unittest.TestCase):
    def test_observe(self) -> None:
        h = HistogramMetric(name="test", description="test histogram", buckets=(0.1, 0.5, 1.0))
        h.observe(0.05)
        h.observe(0.3)
        h.observe(2.0)
        data = h.get()
        assert data["count"] == 3
        assert data["sum"] == pytest.approx(2.35)

    def test_percentile(self) -> None:
        h = HistogramMetric(name="test", description="test histogram")
        for v in [0.1, 0.2, 0.3, 0.4, 0.5]:
            h.observe(v)
        p50 = h.percentile(50)
        assert p50 > 0

    def test_percentile_empty(self) -> None:
        h = HistogramMetric(name="test", description="test histogram")
        assert h.percentile(50) == 0.0

import unittest

import pytest

from src.infrastructure.observability.metrics import (
    CounterMetric,
)


class TestCounterMetric(unittest.TestCase):
    def test_increment(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        c.inc()
        assert c.get() == 1.0

    def test_increment_by_amount(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        c.inc(5.0)
        assert c.get() == 5.0

    def test_negative_increment_raises(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        with pytest.raises(ValueError):
            c.inc(-1.0)

    def test_reset(self) -> None:
        c = CounterMetric(name="test", description="test counter")
        c.inc(10.0)
        c.reset()
        assert c.get() == 0.0

import unittest

from src.infrastructure.observability.config import (
    SamplingStrategy,
)
from src.infrastructure.observability.tracing import (
    SamplingDecision,
)


class TestSamplingStrategy(unittest.TestCase):
    def test_always_on(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.ALWAYS_ON)
        assert sd.should_sample("abc123") is True

    def test_always_off(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.ALWAYS_OFF)
        assert sd.should_sample("abc123") is False

    def test_probabilistic_rate_1(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.PROBABILISTIC, rate=1.0)
        assert sd.should_sample("0000000000000000") is True

    def test_probabilistic_rate_0(self) -> None:
        sd = SamplingDecision(strategy=SamplingStrategy.PROBABILISTIC, rate=0.0)
        assert sd.should_sample("ffffffffffffffff") is False

    def test_should_sample_error(self) -> None:
        sd = SamplingDecision()
        assert sd.should_sample_error() is True

"""Sampling strategies for trace collection.

Supports always-on, always-off, and probabilistic sampling.
Errors are always sampled regardless of strategy.
"""

from __future__ import annotations

from src.infrastructure.observability.config import SamplingStrategy


class SamplingDecision:
    """Determines whether a trace should be sampled."""

    def __init__(
        self,
        strategy: SamplingStrategy = SamplingStrategy.PROBABILISTIC,
        rate: float = 0.1,
    ) -> None:
        self.strategy = strategy
        self.rate = max(0.0, min(1.0, rate))

    def should_sample(self, trace_id: str) -> bool:
        if self.strategy == SamplingStrategy.ALWAYS_ON:
            return True
        if self.strategy == SamplingStrategy.ALWAYS_OFF:
            return False
        if self.strategy == SamplingStrategy.PROBABILISTIC:
            hash_val = int(trace_id[:16], 16) % 10000
            return hash_val < (self.rate * 10000)
        return True

    def should_sample_error(self) -> bool:
        return True

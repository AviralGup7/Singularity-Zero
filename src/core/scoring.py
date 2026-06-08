"""Confidence scoring utilities for validated findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScoringConfig:
    """Bounds for calibrated confidence scores in [0.0, 1.0]."""

    base: float = 0.05
    cap: float = 0.99
    _bonus_ceiling: float = field(default=1.0, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not 0.0 <= self.base <= 1.0:
            raise ValueError(f"base must be in [0,1]; got {self.base!r}")
        if not 0.0 <= self.cap <= 1.0:
            raise ValueError(f"cap must be in [0,1]; got {self.cap!r}")
        if self.base > self.cap:
            raise ValueError(f"base ({self.base}) cannot exceed cap ({self.cap})")


def bounded_confidence(
    *,
    base: float,
    cap: float,
    bonuses: list[float] | None = None,
) -> float:
    """Return a calibrated confidence in [base, cap].

    ``bonuses`` are summed, clamped to ``cap``, then bounded by ``base``.
    """

    cfg = ScoringConfig(base=base, cap=cap)
    raw = cfg.base
    if bonuses:
        raw += sum(bonuses)
    return float(max(cfg.base, min(cfg.cap, raw)))

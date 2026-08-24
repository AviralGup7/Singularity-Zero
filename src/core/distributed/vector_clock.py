"""Lamport Vector Clocks for Distributed Causal Ordering."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CausalOrder(StrEnum):
    BEFORE = "before"
    AFTER = "after"
    CONCURRENT = "concurrent"
    EQUAL = "equal"


@dataclass(frozen=True, slots=True)
class VectorClock:
    """Immutable Vector Clock mapping NodeId -> Logical Counter."""

    clock: tuple[tuple[str, int], ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, d: dict[str, int]) -> VectorClock:
        return cls(clock=tuple(sorted(d.items())))

    def to_dict(self) -> dict[str, int]:
        return dict(self.clock)

    def increment(self, node_id: str) -> VectorClock:
        d = self.to_dict()
        d[node_id] = d.get(node_id, 0) + 1
        return VectorClock.from_dict(d)

    def merge(self, other: VectorClock) -> VectorClock:
        """Take element-wise maximum across both clocks."""
        d1 = self.to_dict()
        d2 = other.to_dict()
        all_nodes = set(d1.keys()) | set(d2.keys())
        merged = {k: max(d1.get(k, 0), d2.get(k, 0)) for k in all_nodes}
        return VectorClock.from_dict(merged)

    def compare(self, other: VectorClock) -> CausalOrder:
        """Determine Lamport causal ordering relative to other."""
        d1 = self.to_dict()
        d2 = other.to_dict()
        if d1 == d2:
            return CausalOrder.EQUAL

        all_nodes = set(d1.keys()) | set(d2.keys())
        less = False
        greater = False

        for k in all_nodes:
            v1 = d1.get(k, 0)
            v2 = d2.get(k, 0)
            if v1 < v2:
                less = True
            elif v1 > v2:
                greater = True

        if less and not greater:
            return CausalOrder.BEFORE
        if greater and not less:
            return CausalOrder.AFTER
        return CausalOrder.CONCURRENT


__all__ = [
    "CausalOrder",
    "VectorClock",
]

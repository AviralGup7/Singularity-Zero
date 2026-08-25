"""Conflict-Free Replicated Data Types (CRDTs) for Distributed State Replication.

Provides mathematically guaranteed commutative, associative, and idempotent
merging (A ⊔ B = B ⊔ A) for zero-conflict state synchronization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GCounter:
    """Grow-Only Counter CRDT."""

    node_counts: tuple[tuple[str, int], ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, d: dict[str, int]) -> GCounter:
        return cls(node_counts=tuple(sorted(d.items())))

    def to_dict(self) -> dict[str, int]:
        return dict(self.node_counts)

    def increment(self, node_id: str, amount: int = 1) -> GCounter:
        if amount < 0:
            raise ValueError("GCounter can only grow")
        d = self.to_dict()
        d[node_id] = d.get(node_id, 0) + amount
        return GCounter.from_dict(d)

    def value(self) -> int:
        return sum(v for _, v in self.node_counts)

    def merge(self, other: GCounter) -> GCounter:
        d1 = self.to_dict()
        d2 = other.to_dict()
        merged = {k: max(d1.get(k, 0), d2.get(k, 0)) for k in set(d1) | set(d2)}
        return GCounter.from_dict(merged)


@dataclass(frozen=True, slots=True)
class ORSet(Generic[T]):  # noqa: UP046
    """Observed-Remove Set CRDT for distributed active scan target pools."""

    # Tuple of (element, tag_uuid)
    adds: tuple[tuple[T, str], ...] = field(default_factory=tuple)
    removes: tuple[str, ...] = field(default_factory=tuple)

    def add(self, item: T, tag: str) -> ORSet[T]:
        return ORSet(adds=self.adds + ((item, tag),), removes=self.removes)

    def remove_tag(self, tag: str) -> ORSet[T]:
        return ORSet(adds=self.adds, removes=self.removes + (tag,))

    def read(self) -> set[T]:
        removed_tags = set(self.removes)
        return {item for item, tag in self.adds if tag not in removed_tags}

    def merge(self, other: ORSet[T]) -> ORSet[T]:
        """Commutative union of add and remove sets."""
        all_adds = tuple(sorted(set(self.adds) | set(other.adds), key=lambda x: str(x[1])))
        all_removes = tuple(sorted(set(self.removes) | set(other.removes)))
        return ORSet(adds=all_adds, removes=all_removes)


__all__ = [
    "GCounter",
    "ORSet",
]

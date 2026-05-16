"""
Cyber Security Test Pipeline - Distributed State (CRDT)
Implements Conflict-free Replicated Data Types for multi-worker synchronization.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class VectorClock:
    """Logical clock for distributed causality tracking."""

    # Fix #324: Use MappingProxyType to prevent mutable default dictionary in frozen dataclass
    versions: MappingProxyType[str, int] = field(default_factory=lambda: MappingProxyType({}))

    def increment(self, node_id: str) -> VectorClock:
        next_v = dict(self.versions)
        next_v[node_id] = next_v.get(node_id, 0) + 1
        return VectorClock(MappingProxyType(next_v))

    def merge(self, other: VectorClock) -> VectorClock:
        next_v = dict(self.versions)
        for nid, v in other.versions.items():
            next_v[nid] = max(next_v.get(nid, 0), v)
        return VectorClock(MappingProxyType(next_v))

    def is_later_than(self, other: VectorClock) -> bool:
        """True if this clock is strictly greater than or equal to 'other'."""
        at_least_one_greater = False
        for nid, v in self.versions.items():
            other_v = other.versions.get(nid, 0)
            if v < other_v:
                return False
            if v > other_v:
                at_least_one_greater = True
        return at_least_one_greater

@dataclass(frozen=True)
class LWWElement:
    """An element with causal versioning."""
    value: Any
    vclock: VectorClock = field(default_factory=VectorClock)
    timestamp: float = field(default_factory=time.time)
    deleted: bool = False

class LWWset(Generic[T]):
    """
    A Last-Write-Wins Element Set CRDT.
    Ensures that multiple workers adding/removing items eventually converge.
    """
    def __init__(self) -> None:
        self._elements: dict[Any, LWWElement] = {}

    def add(
        self,
        item: T,
        timestamp: float | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        # Fix #235: use 'is not None' so timestamp=0.0 (epoch) is preserved.
        ts = timestamp if timestamp is not None else time.time()
        key = self._key(item)
        existing = self._elements.get(key)
        if existing is None or ts > existing.timestamp:
            self._elements[key] = LWWElement(item, vclock or VectorClock(), ts, deleted=False)

    def remove(
        self,
        item: T,
        timestamp: float | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts = timestamp or time.time()
        key = self._key(item)
        existing = self._elements.get(key)
        if existing is None or ts > existing.timestamp:
            self._elements[key] = LWWElement(item, vclock or VectorClock(), ts, deleted=True)

    def merge(self, other: LWWset[T]) -> None:
        """Commutative, Associative, and Idempotent merge."""
        for item, element in other._elements.items():
            existing = self._elements.get(item)
            if existing is None or element.timestamp > existing.timestamp:
                self._elements[item] = element
            elif element.timestamp == existing.timestamp:
                # Fix #323: Use VectorClock as tiebreaker when timestamps are exactly equal
                if element.vclock.is_later_than(existing.vclock):
                    self._elements[item] = element

    def to_set(self) -> set[T]:
        """
        Return the current visible set of non-deleted elements.
        Note: If elements are unhashable (e.g. dicts), use .values() instead.
        """
        return {el.value for el in self._elements.values() if not el.deleted}

    def values(self) -> list[T]:
        """Return visible values, preserving unhashable payloads such as findings."""
        return [el.value for el in self._elements.values() if not el.deleted]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state_delta transfer."""
        return {
            str(k): {"v": el.value, "vc": el.vclock.versions, "ts": el.timestamp, "d": el.deleted}
            for k, el in self._elements.items()
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LWWset[T]:
        lww = cls()
        for k, v in data.items():
            lww._elements[k] = LWWElement(
                v["v"],
                VectorClock(MappingProxyType(v.get("vc", {}))),
                v["ts"],
                v["d"],
            )
        return lww

    @staticmethod
    def _key(item: Any) -> Any:
        try:
            hash(item)
            return item
        except TypeError:
            if isinstance(item, dict):
                return item.get("id") or json.dumps(item, sort_keys=True, default=str)
            return repr(item)

class NeuralState:
    """
    Frontier State Container using CRDTs for global consistency.
    Replaces standard dictionaries for critical pipeline keys.
    """
    def __init__(self) -> None:
        self.subdomains = LWWset[str]()
        self.urls = LWWset[str]()
        self.findings = LWWset[dict[str, Any]]()
        self.metadata: dict[str, Any] = {}

    def apply_delta(self, delta: dict[str, Any]) -> None:
        """Merge a state_delta using CRDT logic."""
        ts = delta.get("_ts", time.time())

        # Fix #388: guard against string being passed instead of a list,
        # which would cause character-by-character iteration.
        if "subdomains" in delta:
            subdomains = delta["subdomains"]
            if isinstance(subdomains, list):
                for sub in subdomains:
                    self.subdomains.add(sub, ts)

        if "urls" in delta:
            urls = delta["urls"]
            if isinstance(urls, list):
                for url in urls:
                    self.urls.add(url, ts)

        if "findings" in delta:
            findings = delta["findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts)

    def get_snapshot(self) -> dict[str, Any]:
        # Fix #355: Sort subdomains and urls for deterministic output across runs.
        return {
            "subdomains": sorted(self.subdomains.to_set()),
            "urls": sorted(self.urls.to_set()),
            "findings": self.findings.values(),
        }

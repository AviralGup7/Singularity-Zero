from __future__ import annotations
import logging
"""Cyber Security Test Pipeline - State Validation
HLC clocks, VectorClock, LWW CRDT set primitives, and utility functions.
"""


import copy
import hashlib
import json
import time
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any, TypeVar

T = TypeVar("T")

try:
    from src.core.frontier import _state_cython  # type: ignore
except ImportError:
    try:
        import _state_cython  # type: ignore
    except ImportError:
        _state_cython = None


@dataclass(frozen=True)
class HybridLogicalClock:
    """Hybrid Logical Clock (HLC) for bounded distributed causality tracking."""

    physical_time: float = field(default_factory=time.monotonic)
    logical_counter: int = 0
    node_id: str = "local"

    def tick(self, now: float | None = None) -> HybridLogicalClock:
        physical_now = now if now is not None else time.monotonic()
        l_new = max(self.physical_time, physical_now)
        c_new = (self.logical_counter + 1) if l_new == self.physical_time else 0
        return HybridLogicalClock(l_new, c_new, self.node_id)

    def update(self, remote: HybridLogicalClock, now: float | None = None) -> HybridLogicalClock:
        physical_now = now if now is not None else time.monotonic()
        l_new = max(self.physical_time, remote.physical_time, physical_now)
        if l_new == self.physical_time == remote.physical_time:
            c_new = max(self.logical_counter, remote.logical_counter) + 1
        elif l_new == self.physical_time:
            c_new = self.logical_counter + 1
        elif l_new == remote.physical_time:
            c_new = remote.logical_counter + 1
        else:
            c_new = 0
        return HybridLogicalClock(l_new, c_new, self.node_id)

    def is_later_than(self, other: HybridLogicalClock) -> bool:
        if self.physical_time > other.physical_time:
            return True
        if self.physical_time < other.physical_time:
            return False
        if self.logical_counter > other.logical_counter:
            return True
        if self.logical_counter < other.logical_counter:
            return False
        return self.node_id > other.node_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "l": self.physical_time,
            "c": self.logical_counter,
            "node": self.node_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> HybridLogicalClock:
        if not data:
            return cls()
        return cls(
            physical_time=float(data.get("l", 0.0)),
            logical_counter=int(data.get("c", 0)),
            node_id=str(data.get("node", "local")),
        )


@dataclass(frozen=True)
class VectorClock:
    """Logical clock kept for interface backwards-compatibility."""

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

    def prune(self, active_node_ids: set[str]) -> VectorClock:
        next_v = {nid: v for nid, v in self.versions.items() if nid in active_node_ids}
        return VectorClock(MappingProxyType(next_v))

    def is_later_than(self, other: VectorClock) -> bool:
        at_least_one_greater = False
        for nid in set(self.versions) | set(other.versions):
            v = self.versions.get(nid, 0)
            other_v = other.versions.get(nid, 0)
            if v < other_v:
                return False
            if v > other_v:
                at_least_one_greater = True
        return at_least_one_greater

    def to_dict(self) -> dict[str, int]:
        return dict(self.versions)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> VectorClock:
        return cls(MappingProxyType({str(k): int(v) for k, v in (data or {}).items()}))


@dataclass(frozen=True)
class LWWElement:
    """An element with causal versioning using Hybrid Logical Clocks."""

    value: Any
    hlc: HybridLogicalClock = field(default_factory=HybridLogicalClock)
    vclock: VectorClock = field(default_factory=VectorClock)
    timestamp: float = field(default_factory=time.time)
    deleted: bool = False


class LWWset[T]:
    """
    A Last-Write-Wins Element Set CRDT.
    Uses Hybrid Logical Clocks (HLC) for deterministic event tie-breaking.
    """

    def __init__(self) -> None:
        self._elements: dict[Any, LWWElement] = {}
        self._clock = HybridLogicalClock(0.0, 0, "local")
        self._lock = RLock()

    def add(
        self,
        item: T,
        timestamp: float | None = None,
        hlc: HybridLogicalClock | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts, clock = self._event_clock(timestamp, hlc)
        key = self._key(item)
        element = LWWElement(_clone_value(item), clock, vclock or VectorClock(), ts, deleted=False)
        with self._lock:
            existing = self._elements.get(key)
            if existing is None or _element_wins(element, existing):
                self._elements[key] = element

    def remove(
        self,
        item: T,
        timestamp: float | None = None,
        hlc: HybridLogicalClock | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts, clock = self._event_clock(timestamp, hlc)
        key = self._key(item)
        element = LWWElement(_clone_value(item), clock, vclock or VectorClock(), ts, deleted=True)
        with self._lock:
            existing = self._elements.get(key)
            if existing is None or _element_wins(element, existing):
                self._elements[key] = element

    def merge(self, other: LWWset[T]) -> None:
        with other._lock:
            incoming = list(other._elements.items())
            other_clock = other._clock
        with self._lock:
            self._clock = self._clock.update(other_clock)
            for item, element in incoming:
                existing = self._elements.get(item)
                if existing is None or _element_wins(element, existing):
                    self._elements[item] = _clone_element(element)

    @property
    def tombstone_count(self) -> int:
        with self._lock:
            return sum(1 for el in self._elements.values() if el.deleted)

    def compact(self, max_tombstone_age_seconds: float = 86400.0) -> int:
        now = time.time()
        with self._lock:
            to_remove = [
                k
                for k, el in self._elements.items()
                if el.deleted and (now - el.timestamp) >= max_tombstone_age_seconds
            ]
            for k in to_remove:
                del self._elements[k]
        return len(to_remove)

    def compact_with_budget(
        self,
        max_tombstone_age_seconds: float,
        budget_ms: float,
        start_time: float,
    ) -> int:
        now = time.time()
        with self._lock:
            tombstones = [
                (k, el.timestamp)
                for k, el in self._elements.items()
                if el.deleted and (now - el.timestamp) >= max_tombstone_age_seconds
            ]
        if not tombstones:
            return 0

        if _state_cython and hasattr(_state_cython, "radix_sort_timestamps"):
            sorted_tombstones = _state_cython.radix_sort_timestamps(tombstones)
        else:
            sorted_tombstones = radix_sort_timestamps(tombstones)

        purged = 0
        for k, _ in sorted_tombstones:
            if (time.time() - start_time) * 1000.0 >= budget_ms:
                break
            with self._lock:
                if k in self._elements:
                    del self._elements[k]
                    purged += 1
        return purged

    def to_set(self) -> set[T]:
        with self._lock:
            return {_clone_value(el.value) for el in self._elements.values() if not el.deleted}

    def values(self) -> list[T]:
        with self._lock:
            return [_clone_value(el.value) for el in self._elements.values() if not el.deleted]

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                str(k): {
                    "v": _clone_value(el.value),
                    "hlc": el.hlc.to_dict(),
                    "vc": el.vclock.to_dict(),
                    "ts": el.timestamp,
                    "d": el.deleted,
                }
                for k, el in self._elements.items()
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LWWset[T]:
        lww = cls()
        for k, v in data.items():
            if not isinstance(v, dict) or "v" not in v:
                continue
            try:
                ts = float(v.get("ts", 0.0))
            except (TypeError, ValueError):
                continue
            hlc_data = v.get("hlc")
            if hlc_data:
                hlc = HybridLogicalClock.from_dict(hlc_data)
            else:
                hlc = HybridLogicalClock(ts, 0, "local")

            element = LWWElement(
                _clone_value(v["v"]),
                hlc,
                VectorClock.from_dict(v.get("vc", {})),
                ts,
                bool(v.get("d", False)),
            )
            lww._elements[k] = element
            if hlc.is_later_than(lww._clock):
                lww._clock = hlc
        return lww

    @property
    def tombstone_count(self) -> int:
        with self._lock:
            return sum(1 for el in self._elements.values() if el.deleted)

    def _event_clock(
        self, timestamp: float | None, hlc: HybridLogicalClock | None
    ) -> tuple[float, HybridLogicalClock]:
        if hlc is not None:
            with self._lock:
                if hlc.is_later_than(self._clock):
                    self._clock = hlc
            return (timestamp if timestamp is not None else hlc.physical_time), hlc
        if timestamp is not None:
            ts = float(timestamp)
            clock = HybridLogicalClock(ts, 0, "local")
            with self._lock:
                if clock.is_later_than(self._clock):
                    self._clock = clock
            return ts, clock
        ts = time.time()
        with self._lock:
            self._clock = self._clock.tick(ts)
            return ts, self._clock

    @staticmethod
    def _key(item: Any) -> Any:
        try:
            hash(item)
            return item
        except TypeError:
            if isinstance(item, dict):
                fid = item.get("id")
                if not fid:
                    stable_parts = [
                        str(item.get("type", "")),
                        str(item.get("title", "")),
                        str(item.get("url", item.get("endpoint", ""))),
                        str(item.get("parameter", "")),
                        str(item.get("method", "")),
                    ]
                    generated_fid = hashlib.sha256(
                        "|".join(stable_parts).encode("utf-8")
                    ).hexdigest()
                    try:
                        item["id"] = generated_fid
                    except TypeError as exc:
                        logging.warning("Operation failed in state_validation.py: %s", exc, exc_info=True)  # noqa: BLE001
                    return generated_fid
                return fid
            return repr(item)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _clone_value[T](value: T) -> T:
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _clone_element(element: LWWElement) -> LWWElement:
    return LWWElement(
        _clone_value(element.value),
        element.hlc,
        element.vclock,
        element.timestamp,
        element.deleted,
    )


def _element_wins(candidate: LWWElement, existing: LWWElement) -> bool:
    if candidate.hlc.is_later_than(existing.hlc):
        return True
    if existing.hlc.is_later_than(candidate.hlc):
        return False
    if candidate.deleted != existing.deleted:
        return candidate.deleted
    return _stable_json(candidate.value) > _stable_json(existing.value)


def stable_digest(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def radix_sort_timestamps(items: list[tuple[Any, float]]) -> list[tuple[Any, float]]:
    if not items:
        return []
    min_ts = min(item[1] for item in items)
    int_items: list[tuple[Any, float, int]] = []
    for key, ts in items:
        int_items.append((key, ts, int((ts - min_ts) * 1000)))

    max_val = max(i[2] for i in int_items)
    if max_val == 0:
        return [(i[0], i[1]) for i in int_items]

    base = 10
    placement = 1
    while placement <= max_val:
        buckets: list[list] = [[] for _ in range(base)]
        for item in int_items:
            buckets[(item[2] // placement) % base].append(item)
        int_items = [item for bucket in buckets for item in bucket]
        placement *= base

    return [(item[0], item[1]) for item in int_items]

"""
Cyber Security Test Pipeline - Distributed State (CRDT)
Implements Hybrid Logical Clocks (HLC) and Conflict-free Replicated Data Types.
Ensures bounded-size distributed causality tracking for cross-datacenter replication.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, TypeVar

try:
    from src.core.frontier import _state_cython  # type: ignore
except ImportError:
    try:
        import _state_cython  # type: ignore
    except ImportError:
        _state_cython = None

T = TypeVar("T")


@dataclass(frozen=True)
class HybridLogicalClock:
    """Hybrid Logical Clock (HLC) for bounded distributed causality tracking."""

    physical_time: float = field(default_factory=time.time)
    logical_counter: int = 0
    node_id: str = "local"

    def tick(self, now: float | None = None) -> HybridLogicalClock:
        """Generate a new HLC tick representing a local event."""
        physical_now = now if now is not None else time.time()
        l_new = max(self.physical_time, physical_now)
        c_new = (self.logical_counter + 1) if l_new == self.physical_time else 0
        return HybridLogicalClock(l_new, c_new, self.node_id)

    def update(self, remote: HybridLogicalClock, now: float | None = None) -> HybridLogicalClock:
        """Merge causality with a remote HLC tick upon message/state receipt."""
        physical_now = now if now is not None else time.time()
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
        """Compare HLC timestamps using causal ordering rules."""
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
        """Serialize HLC properties."""
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
        for nid, v in self.versions.items():
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

    def add(
        self,
        item: T,
        timestamp: float | None = None,
        hlc: HybridLogicalClock | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        clock = hlc if hlc is not None else HybridLogicalClock(ts, 0, "local").tick(ts)
        key = self._key(item)
        existing = self._elements.get(key)
        if existing is None or clock.is_later_than(existing.hlc):
            self._elements[key] = LWWElement(
                item, clock, vclock or VectorClock(), ts, deleted=False
            )

    def remove(
        self,
        item: T,
        timestamp: float | None = None,
        hlc: HybridLogicalClock | None = None,
        vclock: VectorClock | None = None,
    ) -> None:
        ts = timestamp if timestamp is not None else time.time()
        clock = hlc if hlc is not None else HybridLogicalClock(ts, 0, "local").tick(ts)
        key = self._key(item)
        existing = self._elements.get(key)
        if existing is None or clock.is_later_than(existing.hlc):
            self._elements[key] = LWWElement(item, clock, vclock or VectorClock(), ts, deleted=True)

    def merge(self, other: LWWset[T]) -> None:
        """Commutative, Associative, and Idempotent merge using Hybrid Logical Clocks."""
        for item, element in other._elements.items():
            existing = self._elements.get(item)
            if existing is None or element.hlc.is_later_than(existing.hlc):
                self._elements[item] = element
            elif (
                element.hlc.physical_time == existing.hlc.physical_time
                and element.hlc.logical_counter == existing.hlc.logical_counter
            ):
                # Tie-breaker on node_id and JSON stable value string content
                if element.hlc.node_id > existing.hlc.node_id or (
                    element.hlc.node_id == existing.hlc.node_id
                    and _stable_json(element.value) > _stable_json(existing.value)
                ):
                    self._elements[item] = element

    @property
    def tombstone_count(self) -> int:
        return sum(1 for el in self._elements.values() if el.deleted)

    def compact(self, max_tombstone_age_seconds: float = 86400.0) -> int:
        now = time.time()
        to_remove = [
            k
            for k, el in self._elements.items()
            if el.deleted and (now - el.timestamp) > max_tombstone_age_seconds
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
        tombstones = [
            (k, el.timestamp)
            for k, el in self._elements.items()
            if el.deleted and (now - el.timestamp) > max_tombstone_age_seconds
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
            del self._elements[k]
            purged += 1
        return purged

    def to_set(self) -> set[T]:
        return {el.value for el in self._elements.values() if not el.deleted}

    def values(self) -> list[T]:
        return [el.value for el in self._elements.values() if not el.deleted]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state_delta transfer, preserving HLC, vclock and physical timestamps."""
        return {
            str(k): {
                "v": el.value,
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
            hlc_data = v.get("hlc")
            ts = v["ts"]
            if hlc_data:
                hlc = HybridLogicalClock.from_dict(hlc_data)
            else:
                hlc = HybridLogicalClock(ts, 0, "local")

            lww._elements[k] = LWWElement(
                v["v"],
                hlc,
                VectorClock.from_dict(v.get("vc", {})),
                ts,
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
    """Frontier State Container utilizing HLC-backed LWWset CRDTs for global consistency."""

    def __init__(self) -> None:
        self.subdomains = LWWset[str]()
        self.urls = LWWset[str]()
        self.findings = LWWset[dict[str, Any]]()
        self.metadata: dict[str, Any] = {}
        self.last_wal_id: str | None = None
        self.applied_wal_ids: set[str] = set()
        self.created_at: float = time.time()
        self.hlc = HybridLogicalClock(node_id="local")

    def compact(self, max_tombstone_age_seconds: float = 3600.0) -> dict[str, int]:
        purged = {
            "subdomains": self.subdomains.compact(max_tombstone_age_seconds),
            "urls": self.urls.compact(max_tombstone_age_seconds),
            "findings": self.findings.compact(max_tombstone_age_seconds),
        }
        total = sum(purged.values())
        if total > 0:
            from src.core.logging.trace_logging import get_pipeline_logger

            get_pipeline_logger(__name__).info(
                "NeuralState: Compacted %d expired tombstones %s", total, purged
            )
        return purged

    def apply_delta(self, delta: dict[str, Any]) -> None:
        """Merge state_delta using HLC causal tie-breaking logic."""
        wal_id = delta.get("_wal_id") or delta.get("wal_id")
        if isinstance(wal_id, str) and wal_id in self.applied_wal_ids:
            return

        ts = delta.get("_ts", time.time())
        node_id = str(delta.get("_node_id") or delta.get("node_id") or "local")

        # Update local HLC with remote event info
        remote_hlc_dict = delta.get("hlc")
        if remote_hlc_dict:
            remote_hlc = HybridLogicalClock.from_dict(remote_hlc_dict)
            self.hlc = self.hlc.update(remote_hlc, ts)
        else:
            self.hlc = self.hlc.tick(ts)

        vclock = VectorClock().increment(node_id)

        if "subdomains" in delta:
            subdomains = delta["subdomains"]
            if isinstance(subdomains, list):
                for sub in subdomains:
                    self.subdomains.add(sub, ts, self.hlc, vclock)

        if "urls" in delta:
            urls = delta["urls"]
            if isinstance(urls, list):
                for url in urls:
                    self.urls.add(url, ts, self.hlc, vclock)

        if "discovered_urls" in delta:
            urls = delta["discovered_urls"]
            if isinstance(urls, list):
                for url in urls:
                    self.urls.add(url, ts, self.hlc, vclock)

        if "findings" in delta:
            findings = delta["findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts, self.hlc, vclock)

        if "active_scan_findings" in delta:
            findings = delta["active_scan_findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts, self.hlc, vclock)

        if "reportable_findings" in delta:
            findings = delta["reportable_findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts, self.hlc, vclock)

        if "vulnerabilities" in delta:
            findings = delta["vulnerabilities"]
            if isinstance(findings, list):
                for finding in findings:
                    payload = (
                        finding
                        if isinstance(finding, dict)
                        else {"id": str(finding), "title": str(finding)}
                    )
                    self.findings.add(payload, ts, self.hlc, vclock)

        if isinstance(wal_id, str):
            self.applied_wal_ids.add(wal_id)
            self.last_wal_id = wal_id

    def get_snapshot(self) -> dict[str, Any]:
        return {
            "subdomains": sorted(self.subdomains.to_set()),
            "urls": sorted(self.urls.to_set()),
            "findings": self.findings.values(),
        }

    def to_crdt_snapshot(self) -> dict[str, Any]:
        """Serialize complete convergence state, including HLC, tombstones and WAL cursors."""
        return {
            "format": "neural-state-crdt-v3",
            "created_at": getattr(self, "created_at", None) or time.time(),
            "last_wal_id": self.last_wal_id,
            "applied_wal_ids": sorted(self.applied_wal_ids),
            "hlc": self.hlc.to_dict(),
            "sets": {
                "subdomains": self.subdomains.to_dict(),
                "urls": self.urls.to_dict(),
                "findings": self.findings.to_dict(),
            },
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_crdt_snapshot(cls, snapshot: dict[str, Any] | None) -> NeuralState:
        state = cls()
        if not isinstance(snapshot, dict):
            return state

        sets = snapshot.get("sets")
        if isinstance(sets, dict):
            state.subdomains = LWWset.from_dict(sets.get("subdomains", {}) or {})
            state.urls = LWWset.from_dict(sets.get("urls", {}) or {})
            state.findings = LWWset.from_dict(sets.get("findings", {}) or {})
            state.metadata = dict(snapshot.get("metadata", {}) or {})
            state.last_wal_id = snapshot.get("last_wal_id")
            state.applied_wal_ids = {
                str(item) for item in snapshot.get("applied_wal_ids", []) if item is not None
            }
            if isinstance(state.last_wal_id, str):
                state.applied_wal_ids.add(state.last_wal_id)
            if "created_at" in snapshot:
                state.created_at = snapshot["created_at"]
            if "hlc" in snapshot:
                state.hlc = HybridLogicalClock.from_dict(snapshot["hlc"])
            return state

        state.apply_delta(
            {
                "subdomains": list(snapshot.get("subdomains", []) or []),
                "urls": list(snapshot.get("urls", []) or []),
                "findings": list(
                    snapshot.get("findings") or snapshot.get("reportable_findings") or []
                ),
            }
        )
        return state

    def merge(self, other: NeuralState) -> None:
        """Merge another NeuralState causationally using Hybrid Logical Clocks."""
        self.subdomains.merge(other.subdomains)
        self.urls.merge(other.urls)
        self.findings.merge(other.findings)
        self.metadata.update(other.metadata)
        self.applied_wal_ids.update(other.applied_wal_ids)
        self.hlc = self.hlc.update(other.hlc)
        if other.last_wal_id:
            self.last_wal_id = other.last_wal_id


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_digest(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def radix_sort_timestamps(items: list[tuple[Any, float]]) -> list[tuple[Any, float]]:
    if not items:
        return []
    min_ts = min(item[1] for item in items)
    int_items = []
    for key, ts in items:
        val = int((ts - min_ts) * 1000)
        int_items.append((key, ts, val))

    max_val = max(item[2] for item in int_items)
    if max_val == 0:
        return [(item[0], item[1]) for item in int_items]

    base = 10
    placement = 1
    while placement <= max_val:
        buckets: list[list[tuple[Any, float, int]]] = [[] for _ in range(base)]
        for item in int_items:
            digit = (item[2] // placement) % base
            buckets[digit].append(item)
        int_items = []
        for bucket in buckets:
            int_items.extend(bucket)
        placement *= base

    return [(item[0], item[1]) for item in int_items]


class CRDTCompactionBudget:
    def __init__(
        self,
        initial_budget_ms: float = 50.0,
        min_budget_ms: float = 5.0,
        max_budget_ms: float = 500.0,
        target_elapsed_ms: float = 30.0,
    ) -> None:
        self.budget_ms = initial_budget_ms
        self.min_budget_ms = min_budget_ms
        self.max_budget_ms = max_budget_ms
        self.target_elapsed_ms = target_elapsed_ms

    def adjust(self, elapsed_ms: float) -> None:
        if elapsed_ms > self.target_elapsed_ms:
            self.budget_ms = max(self.min_budget_ms, self.budget_ms * 0.75)
        else:
            self.budget_ms = min(self.max_budget_ms, self.budget_ms + 5.0)


def compact_state(
    state: NeuralState,
    budget: CRDTCompactionBudget,
    max_tombstone_age_seconds: float = 3600.0,
) -> dict[str, Any]:
    start_time = time.time()
    budget_ms = budget.budget_ms

    purged_subdomains = state.subdomains.compact_with_budget(
        max_tombstone_age_seconds, budget_ms, start_time
    )

    elapsed_so_far = (time.time() - start_time) * 1000.0
    purged_urls = 0
    if elapsed_so_far < budget_ms:
        purged_urls = state.urls.compact_with_budget(
            max_tombstone_age_seconds, budget_ms - elapsed_so_far, start_time
        )

    elapsed_so_far = (time.time() - start_time) * 1000.0
    purged_findings = 0
    if elapsed_so_far < budget_ms:
        purged_findings = state.findings.compact_with_budget(
            max_tombstone_age_seconds, budget_ms - elapsed_so_far, start_time
        )

    total_elapsed_ms = (time.time() - start_time) * 1000.0
    budget.adjust(total_elapsed_ms)

    return {
        "subdomains": purged_subdomains,
        "urls": purged_urls,
        "findings": purged_findings,
        "elapsed_ms": total_elapsed_ms,
        "new_budget_ms": budget.budget_ms,
    }

"""
Cyber Security Test Pipeline - Distributed State (CRDT)
Implements Conflict-free Replicated Data Types for multi-worker synchronization.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, TypeVar

try:
    import _state_cython
except ImportError:
    _state_cython = None

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

    def prune(self, active_node_ids: set[str]) -> VectorClock:
        """Remove entries for nodes that are no longer part of the mesh."""
        next_v = {nid: v for nid, v in self.versions.items() if nid in active_node_ids}
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

    def to_dict(self) -> dict[str, int]:
        """Return a JSON/MessagePack-friendly representation."""
        return dict(self.versions)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> VectorClock:
        return cls(MappingProxyType({str(k): int(v) for k, v in (data or {}).items()}))


@dataclass(frozen=True)
class LWWElement:
    """An element with causal versioning."""

    value: Any
    vclock: VectorClock = field(default_factory=VectorClock)
    timestamp: float = field(default_factory=time.time)
    deleted: bool = False


class LWWset[T]:
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
        # Match add(): preserve timestamp=0.0 (epoch)
        ts = timestamp if timestamp is not None else time.time()
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
                if element.vclock.is_later_than(existing.vclock) or (
                    element.vclock.versions == existing.vclock.versions
                    and _stable_json(element.value) > _stable_json(existing.value)
                ):
                    self._elements[item] = element

    @property
    def tombstone_count(self) -> int:
        """Count the number of deleted items (tombstones) currently in memory."""
        return sum(1 for el in self._elements.values() if el.deleted)

    def compact(self, max_tombstone_age_seconds: float = 86400.0) -> int:
        """
        Purge tombstones (deleted items) older than the threshold.
        Returns the number of elements purged.
        """
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
        """
        Purge tombstones (deleted items) older than the threshold within the time budget.
        Uses radix sort to sort tombstones by age for deterministic compaction.
        """
        now = time.time()
        tombstones = [
            (k, el.timestamp)
            for k, el in self._elements.items()
            if el.deleted and (now - el.timestamp) > max_tombstone_age_seconds
        ]
        if not tombstones:
            return 0

        # Sort tombstones using radix sort (or cython path if available)
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
            str(k): {"v": el.value, "vc": el.vclock.to_dict(), "ts": el.timestamp, "d": el.deleted}
            for k, el in self._elements.items()
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LWWset[T]:
        lww = cls()
        for k, v in data.items():
            lww._elements[k] = LWWElement(
                v["v"],
                VectorClock.from_dict(v.get("vc", {})),
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
        self.last_wal_id: str | None = None
        self.applied_wal_ids: set[str] = set()
        self.created_at: float = time.time()

    def compact(self, max_tombstone_age_seconds: float = 3600.0) -> dict[str, int]:
        """
        Safely purge old tombstones across all CRDT sets.
        Default threshold is 1 hour for high-velocity scans.
        """
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
        """Merge a state_delta using CRDT logic."""
        wal_id = delta.get("_wal_id") or delta.get("wal_id")
        if isinstance(wal_id, str) and wal_id in self.applied_wal_ids:
            return

        ts = delta.get("_ts", time.time())
        node_id = str(delta.get("_node_id") or delta.get("node_id") or "local")
        vclock = VectorClock().increment(node_id)

        # Fix #388: guard against string being passed instead of a list,
        # which would cause character-by-character iteration.
        if "subdomains" in delta:
            subdomains = delta["subdomains"]
            if isinstance(subdomains, list):
                for sub in subdomains:
                    self.subdomains.add(sub, ts, vclock)

        if "urls" in delta:
            urls = delta["urls"]
            if isinstance(urls, list):
                for url in urls:
                    self.urls.add(url, ts, vclock)

        if "discovered_urls" in delta:
            urls = delta["discovered_urls"]
            if isinstance(urls, list):
                for url in urls:
                    self.urls.add(url, ts, vclock)

        if "findings" in delta:
            findings = delta["findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts, vclock)

        if "active_scan_findings" in delta:
            findings = delta["active_scan_findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts, vclock)

        if "reportable_findings" in delta:
            findings = delta["reportable_findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self.findings.add(finding, ts, vclock)

        if "vulnerabilities" in delta:
            findings = delta["vulnerabilities"]
            if isinstance(findings, list):
                for finding in findings:
                    payload = (
                        finding
                        if isinstance(finding, dict)
                        else {"id": str(finding), "title": str(finding)}
                    )
                    self.findings.add(payload, ts, vclock)

        if isinstance(wal_id, str):
            self.applied_wal_ids.add(wal_id)
            self.last_wal_id = wal_id

    def get_snapshot(self) -> dict[str, Any]:
        # Fix #355: Sort subdomains and urls for deterministic output across runs.
        return {
            "subdomains": sorted(self.subdomains.to_set()),
            "urls": sorted(self.urls.to_set()),
            "findings": self.findings.values(),
        }

    def to_crdt_snapshot(self) -> dict[str, Any]:
        """Serialize the complete convergence state, including tombstones and WAL cursors."""
        return {
            "format": "neural-state-crdt-v2",
            "created_at": getattr(self, "created_at", None) or time.time(),
            "last_wal_id": self.last_wal_id,
            "applied_wal_ids": sorted(self.applied_wal_ids),
            "sets": {
                "subdomains": self.subdomains.to_dict(),
                "urls": self.urls.to_dict(),
                "findings": self.findings.to_dict(),
            },
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_crdt_snapshot(cls, snapshot: dict[str, Any] | None) -> NeuralState:
        """Restore a full CRDT snapshot or a legacy value-only snapshot."""
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
        """Merge another NeuralState without losing tombstones or replay cursors."""
        self.subdomains.merge(other.subdomains)
        self.urls.merge(other.urls)
        self.findings.merge(other.findings)
        self.metadata.update(other.metadata)
        self.applied_wal_ids.update(other.applied_wal_ids)
        if other.last_wal_id:
            self.last_wal_id = other.last_wal_id


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_digest(value: Any) -> str:
    """Stable content address for deduplication and evidence records."""
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def radix_sort_timestamps(items: list[tuple[Any, float]]) -> list[tuple[Any, float]]:
    """
    Sorts a list of (key, timestamp) tuples by timestamp using a radix sort.
    We convert the timestamp to an integer of millisecond scale.
    """
    if not items:
        return []
    # Map to integer representations
    min_ts = min(item[1] for item in items)
    # Convert to non-negative integers relative to min_ts
    int_items = []
    for key, ts in items:
        # millisecond precision as integer
        val = int((ts - min_ts) * 1000)
        int_items.append((key, ts, val))

    # Standard Radix Sort (LSD)
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
    """
    Tracks and dynamically adjusts the compaction budget (max execution time)
    using an Additive Increase / Multiplicative Decrease (AIMD) algorithm.
    """

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
        """Adjust budget using AIMD based on elapsed execution time."""
        if elapsed_ms > self.target_elapsed_ms:
            # Backoff: Multiplicative Decrease
            self.budget_ms = max(self.min_budget_ms, self.budget_ms * 0.75)
        else:
            # Additive Increase
            self.budget_ms = min(self.max_budget_ms, self.budget_ms + 5.0)


def compact_state(
    state: NeuralState,
    budget: CRDTCompactionBudget,
    max_tombstone_age_seconds: float = 3600.0,
) -> dict[str, Any]:
    """
    Compact tombstones across all sets in NeuralState within the specified CRDTCompactionBudget.
    Uses radix sort and AIMD budget gating to ensure low latency.
    """
    start_time = time.time()
    budget_ms = budget.budget_ms

    # Compact each LWWset while keeping within the remaining budget
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

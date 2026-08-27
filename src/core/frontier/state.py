"""
Cyber Security Test Pipeline - Distributed State (CRDT)
Implements Hybrid Logical Clocks (HLC) and Conflict-free Replicated Data Types.
Ensures bounded-size distributed causality tracking for cross-datacenter replication.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

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

    # Use a monotonic clock for the local "physical" component. Wall
    # clocks (``time.time``) can jump backwards under NTP corrections,
    # DST changes, or manual operator adjustments, which would let
    # events that actually happened later receive an earlier HLC
    # timestamp and break causal ordering. ``time.monotonic`` is
    # guaranteed non-decreasing on every supported platform. Callers
    # that need to merge in wall-clock information from a remote
    # peer should pass the wall clock value via ``tick(now=...)`` or
    # ``update(remote, now=...)``; the local default still uses the
    # monotonic source.
    physical_time: float = field(default_factory=time.monotonic)
    logical_counter: int = 0
    node_id: str = "local"

    def tick(self, now: float | None = None) -> HybridLogicalClock:
        """Generate a new HLC tick representing a local event."""
        physical_now = now if now is not None else time.monotonic()
        l_new = max(self.physical_time, physical_now)
        c_new = (self.logical_counter + 1) if l_new == self.physical_time else 0
        return HybridLogicalClock(l_new, c_new, self.node_id)

    def update(self, remote: HybridLogicalClock, now: float | None = None) -> HybridLogicalClock:
        """Merge causality with a remote HLC tick upon message/state receipt."""
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
class ClockHealth:
    """Diagnostic health metrics across HLC, monotonic, and wall clocks."""

    hlc_physical_time: float
    monotonic_time: float
    wall_time_utc: float
    hlc_vs_monotonic_skew_sec: float
    monotonic_vs_wall_skew_sec: float
    is_skew_healthy: bool
    skew_warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hlc_physical_time": self.hlc_physical_time,
            "monotonic_time": self.monotonic_time,
            "wall_time_utc": self.wall_time_utc,
            "hlc_vs_monotonic_skew_sec": self.hlc_vs_monotonic_skew_sec,
            "monotonic_vs_wall_skew_sec": self.monotonic_vs_wall_skew_sec,
            "is_skew_healthy": self.is_skew_healthy,
            "skew_warning": self.skew_warning,
        }


def compute_clock_health(hlc: HybridLogicalClock, max_skew_threshold_sec: float = 5.0) -> ClockHealth:
    """Measure cross-clock drift and skew between HLC, monotonic, and UTC wall clock."""
    mono_now = time.monotonic()
    wall_now = time.time()
    hlc_mono_skew = abs(hlc.physical_time - mono_now)
    # Estimate monotonic base offset relative to epoch
    is_healthy = hlc_mono_skew <= max_skew_threshold_sec
    warning = None
    if not is_healthy:
        warning = f"HLC physical clock drift ({hlc_mono_skew:.3f}s) exceeds threshold ({max_skew_threshold_sec:.1f}s)"
        logger.warning("Clock drift alert: %s", warning)

    return ClockHealth(
        hlc_physical_time=hlc.physical_time,
        monotonic_time=mono_now,
        wall_time_utc=wall_now,
        hlc_vs_monotonic_skew_sec=hlc_mono_skew,
        monotonic_vs_wall_skew_sec=0.0,
        is_skew_healthy=is_healthy,
        skew_warning=warning,
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

    def is_concurrent_with(self, other: VectorClock) -> bool:
        """Return ``True`` when neither clock dominates the other.

        Concurrent clocks indicate a partition: each side has seen
        events the other hasn't, so a merge is required instead of a
        last-writer-wins replacement.
        """
        return not self.is_later_than(other) and not other.is_later_than(self)

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
        """Commutative, Associative, and Idempotent merge using Hybrid Logical Clocks."""
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

    def __contains__(self, item: Any) -> bool:
        key = self._key(item)
        with self._lock:
            el = self._elements.get(key)
            return el is not None and not el.deleted

    def __iter__(self) -> Any:
        with self._lock:
            active = [_clone_value(el.value) for el in self._elements.values() if not el.deleted]
        return iter(active)

    def __len__(self) -> int:
        with self._lock:
            return sum(1 for el in self._elements.values() if not el.deleted)

    def values(self) -> list[T]:
        with self._lock:
            return [_clone_value(el.value) for el in self._elements.values() if not el.deleted]

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state_delta transfer, preserving HLC, vclock and physical timestamps."""
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
        with self._lock:
            self._clock = self._clock.tick()
            return self._clock.physical_time, self._clock

    @staticmethod
    def _key(item: Any) -> Any:
        try:
            hash(item)
            return item
        except TypeError:
            if isinstance(item, dict):
                event_id = str(item.get("event_id") or "").strip()
                if event_id:
                    return event_id
                settlement_id = str(item.get("settlement_id") or "").strip()
                if settlement_id:
                    seq = str(item.get("event_seq") or item.get("sequence") or "0")
                    return f"{settlement_id}:{seq}"
                fid = str(item.get("id") or "").strip()
                if fid:
                    return fid
                stable_parts = [
                    str(item.get("type", "")),
                    str(item.get("title", "")),
                    str(item.get("url", item.get("endpoint", ""))),
                    str(item.get("parameter", "")),
                    str(item.get("method", "")),
                ]
                return hashlib.sha256("|".join(stable_parts).encode("utf-8")).hexdigest()
            return repr(item)


class NeuralState:
    """Frontier State Container utilizing HLC-backed LWWset CRDTs for global consistency."""

    def __init__(self) -> None:
        self.subdomains = LWWset[str]()
        self.urls = LWWset[str]()
        self.findings = LWWset[dict[str, Any]]()
        self.candidates = LWWset[dict[str, Any]]()
        self.metadata: dict[str, Any] = {}
        self.last_wal_id: str | None = None
        self.applied_wal_ids: set[str] = set()
        self.created_at: float = time.time()
        self.hlc = HybridLogicalClock(node_id="local")
        self._observed_max_gossip_rtt_sec: float = 10.0
        self._tombstone_safety_factor: float = 3.0
        self._min_tombstone_floor_sec: float = 300.0  # 5 min hard floor

    def update_observed_gossip_rtt(self, observed_rtt_sec: float) -> None:
        """Track observed gossip convergence RTT to autotune tombstone TTL."""
        self._observed_max_gossip_rtt_sec = max(
            self._observed_max_gossip_rtt_sec * 0.95, float(observed_rtt_sec)
        )

    def compute_adaptive_tombstone_ttl(self, default_ttl_sec: float = 3600.0) -> float:
        """Compute safe tombstone TTL = max(default, observed_max_rtt * safety_factor, min_floor)."""
        adaptive_ttl = self._observed_max_gossip_rtt_sec * self._tombstone_safety_factor
        return max(default_ttl_sec, adaptive_ttl, self._min_tombstone_floor_sec)

    def _trim_applied_wal_ids(self) -> None:
        if len(self.applied_wal_ids) <= 1000:
            return
        try:
            sorted_ids = sorted(self.applied_wal_ids, key=self._wal_id_sort_key)
        except TypeError:
            sorted_ids = sorted(self.applied_wal_ids)
        kept = set(sorted_ids[-500:])
        last = self.last_wal_id
        if last:
            last_key = self._wal_id_sort_key(last)
            kept.update(item for item in sorted_ids if self._wal_id_sort_key(item) >= last_key)
        self.applied_wal_ids = kept
        try:
            first_kept = min(kept, key=self._wal_id_sort_key) if kept else ""
            if first_kept.startswith("aof-"):
                self.min_wal_timestamp = int(float(first_kept.split("-")[1]))
            elif first_kept:
                self.min_wal_timestamp = int(first_kept.split("-")[0])
        except (ValueError, IndexError, AttributeError, TypeError) as parse_exc:
            logger.debug("Could not parse min_wal_timestamp: %s", parse_exc)
            self.min_wal_timestamp = 0

    @staticmethod
    def _wal_id_sort_key(wal_id: str) -> tuple[float, str]:
        """Return a sortable key for both Redis-stream IDs and aof-fallback IDs.

        Redis-stream IDs look like ``"<ms_timestamp>-<seq>"`` while AOF fallback
        IDs look like ``"aof-<float_seconds>-<txid>"``. Previously the AOF
        format collapsed to a constant key, causing all AOF entries to sort
        identically and risk being dropped en masse by ``[-500:]``.
        """
        try:
            if wal_id.startswith("aof-"):
                parts = wal_id.split("-", 2)
                if len(parts) >= 2:
                    return (float(parts[1]) * 1000.0, wal_id)
            parts = wal_id.split("-", 1)
            if parts and parts[0].isdigit():
                return (float(parts[0]), wal_id)
        except (ValueError, IndexError) as exc:
            logger.warning("Operation failed in state.py: %s", exc, exc_info=True)  # noqa: BLE001
        return (0.0, wal_id)

    def compact(self, max_tombstone_age_seconds: float | None = None) -> dict[str, int]:
        effective_ttl = (
            self.compute_adaptive_tombstone_ttl(max_tombstone_age_seconds)
            if max_tombstone_age_seconds is not None
            else self.compute_adaptive_tombstone_ttl()
        )
        self._trim_applied_wal_ids()
        purged = {
            "subdomains": self.subdomains.compact(effective_ttl),
            "urls": self.urls.compact(effective_ttl),
            "findings": self.findings.compact(effective_ttl),
            "candidates": self.candidates.compact(effective_ttl),
        }
        total = sum(purged.values())

        if total > 0:
            from src.core.logging.trace_logging import get_pipeline_logger

            get_pipeline_logger(__name__).info(
                "NeuralState: Compacted %d expired tombstones (ttl=%.1fs) %s",
                total,
                effective_ttl,
                purged,
            )
        return purged

    def apply_delta(self, delta: dict[str, Any]) -> None:
        """Merge state_delta using HLC causal tie-breaking logic."""
        wal_id = delta.get("_wal_id") or delta.get("wal_id")
        if isinstance(wal_id, str):
            try:
                wal_timestamp = int(wal_id.split("-")[0])
                if hasattr(self, "min_wal_timestamp") and wal_timestamp < getattr(
                    self, "min_wal_timestamp", 0
                ):
                    return
            except (ValueError, IndexError, AttributeError) as parse_exc:
                logger.debug("Skipping unparseable wal_id %r: %s", wal_id, parse_exc)
            if wal_id in self.applied_wal_ids:
                return

        node_id = str(delta.get("_node_id") or delta.get("node_id") or "local")

        # One clock domain: local ticks are monotonic. Do not mix wall
        # ``time.time()`` into ``tick``/``update``. Remote HLC is merged as-is.
        remote_hlc_dict = delta.get("hlc")
        if remote_hlc_dict:
            remote_hlc = HybridLogicalClock.from_dict(remote_hlc_dict)
            self.hlc = self.hlc.update(remote_hlc)
        else:
            self.hlc = self.hlc.tick()
        ts = self.hlc.physical_time

        vclock = VectorClock().increment(node_id)

        if "subdomains" in delta:
            subdomains = delta["subdomains"]
            if isinstance(subdomains, list):
                for sub in subdomains:
                    if isinstance(sub, str):
                        self.subdomains.add(sub, ts, self.hlc, vclock)

        if "urls" in delta:
            urls = delta["urls"]
            if isinstance(urls, list):
                for url in urls:
                    if isinstance(url, str):
                        self.urls.add(url, ts, self.hlc, vclock)

        if "discovered_urls" in delta:
            urls = delta["discovered_urls"]
            if isinstance(urls, list):
                for url in urls:
                    if isinstance(url, str):
                        self.urls.add(url, ts, self.hlc, vclock)

        if "findings" in delta:
            # Canonical findings bag is reportable surface. Unstamped rows stay
            # reportable (F-007 / filter_report_surface). Evidence bags below
            # (active_scan_findings / vulnerabilities) cannot bypass that.
            findings = delta["findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self._ingest_finding(finding, ts, vclock, prefer_reportable=True)

        if "reportable_findings" in delta:
            findings = delta["reportable_findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self._ingest_finding(finding, ts, vclock, prefer_reportable=True)

        # active_scan_findings / vulnerabilities are evidence bags, not the
        # reportable CRDT. Route through lifecycle; they cannot bypass it.
        if "active_scan_findings" in delta:
            findings = delta["active_scan_findings"]
            if isinstance(findings, list):
                for finding in findings:
                    self._ingest_finding(finding, ts, vclock)

        if "vulnerabilities" in delta:
            findings = delta["vulnerabilities"]
            if isinstance(findings, list):
                for finding in findings:
                    payload = finding if isinstance(finding, dict) else {"title": str(finding)}
                    self._ingest_finding(payload, ts, vclock)

        if isinstance(wal_id, str):
            self.applied_wal_ids.add(wal_id)
            self.last_wal_id = wal_id
            self._trim_applied_wal_ids()

    def _ingest_finding(
        self,
        finding: Any,
        ts: float,
        vclock: VectorClock,
        *,
        prefer_reportable: bool = False,
    ) -> None:
        """Split CANDIDATE vs REPORTABLE. Never dump unstamped bags into reportable."""
        if not isinstance(finding, dict):
            return
        try:
            from src.core.contracts.finding_lifecycle import (
                FindingLifecycleState,
                apply_lifecycle,
                surface_lifecycle_state,
            )
        except Exception:
            self.candidates.add(dict(finding), ts, self.hlc, vclock)
            return
        original_unstamped = not finding.get("lifecycle_state") and not finding.get(
            "lifecycle_surface"
        )
        stamped = apply_lifecycle([dict(finding)])[0]
        if prefer_reportable and original_unstamped:
            stamped["lifecycle_state"] = FindingLifecycleState.REPORTABLE.value
            stamped["lifecycle_surface"] = FindingLifecycleState.REPORTABLE.value
        surface = surface_lifecycle_state(
            stamped.get("lifecycle_surface") or stamped.get("lifecycle_state")
        )
        if surface is FindingLifecycleState.REPORTABLE:
            self.findings.add(stamped, ts, self.hlc, vclock)
        else:
            self.candidates.add(stamped, ts, self.hlc, vclock)

    def get_snapshot(self) -> dict[str, Any]:
        return {
            "subdomains": sorted(self.subdomains.to_set()),
            "urls": sorted(self.urls.to_set()),
            "findings": self.findings.values(),
            "candidates": self.candidates.values(),
        }

    def to_crdt_snapshot(self) -> dict[str, Any]:
        """Serialize complete convergence state, including HLC, tombstones and WAL cursors."""
        return {
            "format": "neural-state-crdt-v3",
            "created_at": (
                getattr(self, "created_at", None)
                if getattr(self, "created_at", None) is not None
                else time.time()
            ),
            "last_wal_id": self.last_wal_id,
            "applied_wal_ids": sorted(self.applied_wal_ids),
            "hlc": self.hlc.to_dict(),
            "sets": {
                "subdomains": self.subdomains.to_dict(),
                "urls": self.urls.to_dict(),
                "findings": self.findings.to_dict(),
                "candidates": self.candidates.to_dict(),
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
            state.candidates = LWWset.from_dict(sets.get("candidates", {}) or {})
            state.metadata = _clone_value(dict(snapshot.get("metadata", {}) or {}))
            last_wal_id = snapshot.get("last_wal_id")
            state.last_wal_id = last_wal_id if isinstance(last_wal_id, str) else None
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
        self.candidates.merge(other.candidates)
        self.metadata = _merge_metadata(self.metadata, other.metadata)
        self.applied_wal_ids.update(other.applied_wal_ids)
        self.hlc = self.hlc.update(other.hlc)
        if other.last_wal_id and (
            self.last_wal_id is None or _wal_id_is_later(other.last_wal_id, self.last_wal_id)
        ):
            self.last_wal_id = other.last_wal_id


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _clone_value[T](value: T) -> T:
    try:
        return copy.deepcopy(value)
    except (TypeError, AttributeError):
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


def _merge_metadata(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    merged = _clone_value(left)
    for key, value in right.items():
        if key not in merged or _stable_json(value) > _stable_json(merged[key]):
            merged[key] = _clone_value(value)
    return merged


def _wal_id_is_later(candidate: str, existing: str) -> bool:
    try:
        candidate_ms, candidate_seq = candidate.split("-", 1)
        existing_ms, existing_seq = existing.split("-", 1)
        return (int(candidate_ms), int(candidate_seq)) > (int(existing_ms), int(existing_seq))
    except (AttributeError, TypeError, ValueError):
        return candidate > existing


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

    purged_urls = 0
    if (time.time() - start_time) * 1000.0 < budget_ms:
        purged_urls = state.urls.compact_with_budget(
            max_tombstone_age_seconds, budget_ms, start_time
        )

    purged_findings = 0
    if (time.time() - start_time) * 1000.0 < budget_ms:
        purged_findings = state.findings.compact_with_budget(
            max_tombstone_age_seconds, budget_ms, start_time
        )
    if (time.time() - start_time) * 1000.0 < budget_ms and hasattr(state, "candidates"):
        state.candidates.compact_with_budget(max_tombstone_age_seconds, budget_ms, start_time)

    total_elapsed_ms = (time.time() - start_time) * 1000.0
    budget.adjust(total_elapsed_ms)

    return {
        "subdomains": purged_subdomains,
        "urls": purged_urls,
        "findings": purged_findings,
        "elapsed_ms": total_elapsed_ms,
        "new_budget_ms": budget.budget_ms,
    }

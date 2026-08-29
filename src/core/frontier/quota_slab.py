"""Explicit quota slab lease/reclaim for I26 (multi-Raft).

Wraps GlobalBudgetAggregate slab accounting with epoch + monotonic expiry
so a dead partition cannot hold SlabReserved forever.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SlabLease:
    slab_id: str
    partition_id: str
    epoch: int
    units: int
    expires_at_mono: float
    status: str = "RESERVED"


class QuotaSlabAllocator:
    """Track SlabId -> (partition, epoch, expires_at_mono, units)."""

    def __init__(self, budget: Any | None = None, *, default_ttl_seconds: float = 300.0) -> None:
        self.budget = budget
        self.default_ttl_seconds = float(default_ttl_seconds)
        self._lock = threading.RLock()
        self._slabs: dict[str, SlabLease] = {}

    def reserve(
        self,
        slab_id: str,
        partition_id: str,
        units: int,
        *,
        epoch: int = 1,
        ttl_seconds: float | None = None,
        now_mono: float | None = None,
    ) -> SlabLease | None:
        now = time.monotonic() if now_mono is None else float(now_mono)
        ttl = self.default_ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        if units <= 0:
            return None
        with self._lock:
            if self.budget is not None and hasattr(self.budget, "allocate_quota_slab"):
                ok, _msg = self.budget.allocate_quota_slab(slab_id, partition_id, units)
                if not ok:
                    return None
            lease = SlabLease(
                slab_id=str(slab_id),
                partition_id=str(partition_id),
                epoch=int(epoch),
                units=int(units),
                expires_at_mono=now + ttl,
            )
            self._slabs[slab_id] = lease
            return lease

    def renew(
        self, slab_id: str, *, ttl_seconds: float | None = None, now_mono: float | None = None
    ) -> bool:
        now = time.monotonic() if now_mono is None else float(now_mono)
        ttl = self.default_ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        with self._lock:
            lease = self._slabs.get(slab_id)
            if lease is None or lease.status != "RESERVED":
                return False
            if lease.expires_at_mono < now:
                return False
            lease.expires_at_mono = now + ttl
            return True

    def reclaim(
        self,
        slab_id: str,
        *,
        consumed_units: int = 0,
        reason: str = "",
    ) -> bool:
        with self._lock:
            lease = self._slabs.get(slab_id)
            if lease is None:
                return False
            if self.budget is not None and hasattr(self.budget, "reclaim_quota_slab"):
                ok, _msg = self.budget.reclaim_quota_slab(slab_id, consumed_units=consumed_units)
                if not ok:
                    logger.debug("quota slab reclaim refused %s: %s", slab_id, _msg)
            lease.status = "RECLAIMED"
            return True

    def gc_expired(self, *, now_mono: float | None = None) -> list[str]:
        now = time.monotonic() if now_mono is None else float(now_mono)
        reclaimed: list[str] = []
        with self._lock:
            expired = [
                sid
                for sid, lease in self._slabs.items()
                if lease.status == "RESERVED" and lease.expires_at_mono < now
            ]
        for sid in expired:
            if self.reclaim(sid, consumed_units=0, reason="ttl"):
                reclaimed.append(sid)
        return reclaimed

    def reserved_units(self) -> int:
        with self._lock:
            return sum(s.units for s in self._slabs.values() if s.status == "RESERVED")


class BudgetModeTransitionError(ValueError):
    """I5/I26 conservation would break across a mode switch."""


def transition_accounting_mode(
    *,
    total: int,
    consumed: int,
    outstanding: int,
    available: int,
    slab_reserved: int = 0,
    slab_units: int = 0,
    to_multi_raft: bool = True,
) -> dict[str, int]:
    """Atomically move units between Available and SlabReserved.

    I5: Total = Consumed + Outstanding + Available
    I26: Total = Consumed + Outstanding + SlabReserved + Available

    The returned snapshot satisfies the destination formula. No intermediate
    dict is published; callers must persist this mapping as one WAL command.
    """
    t = int(total)
    c = int(consumed)
    o = int(outstanding)
    a = int(available)
    s = int(slab_reserved)
    move = int(slab_units)
    if t < 0 or c < 0 or o < 0 or a < 0 or s < 0 or move < 0:
        raise BudgetModeTransitionError("I39: negative budget component")
    if to_multi_raft:
        if c + o + a != t:
            raise BudgetModeTransitionError(
                f"I39: I5 preimage broken C+O+A={c + o + a} != total={t}"
            )
        if move > a:
            raise BudgetModeTransitionError("I39: slab_units exceed Available")
        a2 = a - move
        s2 = s + move
        if c + o + s2 + a2 != t:
            raise BudgetModeTransitionError("I39: I26 postimage broken")
        return {
            "total": t,
            "consumed": c,
            "outstanding": o,
            "available": a2,
            "slab_reserved": s2,
        }
    if c + o + s + a != t:
        raise BudgetModeTransitionError(
            f"I39: I26 preimage broken C+O+S+A={c + o + s + a} != total={t}"
        )
    a2 = a + s
    if c + o + a2 != t:
        raise BudgetModeTransitionError("I39: I5 postimage broken")
    return {
        "total": t,
        "consumed": c,
        "outstanding": o,
        "available": a2,
        "slab_reserved": 0,
    }


__all__ = [
    "BudgetModeTransitionError",
    "QuotaSlabAllocator",
    "SlabLease",
    "transition_accounting_mode",
]

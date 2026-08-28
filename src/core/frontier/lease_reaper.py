"""Authoritative lease reaper (I5 / I28).

Runs on the leader (and on recovery READY) with tick = max(250ms, ttl/4).
RESERVED/ACTIVE past ``deadline_mono`` transition to EXPIRED then COMPENSATED
via CompensationLedger. Never trusts wall-clock.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.core.frontier.compensation_log import CompensationLedger
from src.core.frontier.lease_status import (
    OUTSTANDING,
    LeaseStatus,
    can_transition,
    normalize_lease_status,
    require_transition,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ReapableLease:
    reservation_id: str
    lease_id: str
    status: LeaseStatus
    deadline_mono: float
    units: int = 0


LeaseSource = Callable[[], list[ReapableLease]]
LeaseMutator = Callable[[ReapableLease, LeaseStatus], None]


@dataclass
class LeaseReaper:
    """Background monotonic reaper. Safe to call ``tick()`` from tests."""

    ledger: CompensationLedger
    source: LeaseSource
    mutate: LeaseMutator | None = None
    release: Any | None = None
    min_tick_seconds: float = 0.25
    _last_tick_mono: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    reaped: int = field(default=0, init=False)

    def tick(self, *, now_mono: float | None = None, lease_ttl: float = 1.0) -> int:
        """Expire and compensate stranded outstanding leases. Returns count reaped."""
        now = time.monotonic() if now_mono is None else float(now_mono)
        interval = max(self.min_tick_seconds, float(lease_ttl) / 4.0)
        with self._lock:
            if self._last_tick_mono and now - self._last_tick_mono < interval:
                return 0
            self._last_tick_mono = now
        return self._reap(now)

    def _reap(self, now_mono: float) -> int:
        count = 0
        try:
            leases = list(self.source() or [])
        except Exception as exc:
            logger.warning("LeaseReaper source failed: %s", exc)
            return 0
        for lease in leases:
            try:
                status = normalize_lease_status(lease.status)
            except ValueError:
                continue
            if status not in OUTSTANDING:
                continue
            if lease.deadline_mono > now_mono:
                continue
            if can_transition(status, LeaseStatus.EXPIRED):
                try:
                    require_transition(status, LeaseStatus.EXPIRED)
                    if self.mutate is not None:
                        self.mutate(lease, LeaseStatus.EXPIRED)
                    status = LeaseStatus.EXPIRED
                except Exception as exc:
                    logger.warning("LeaseReaper expire failed for %s: %s", lease.lease_id, exc)
                    continue
            try:
                self.ledger.compensate(
                    lease.reservation_id,
                    lease.lease_id,
                    reason="lease_reaper_deadline",
                    release=self.release,
                )
                if self.mutate is not None and can_transition(status, LeaseStatus.COMPENSATED):
                    self.mutate(lease, LeaseStatus.COMPENSATED)
                count += 1
            except Exception as exc:
                logger.warning("LeaseReaper compensate failed for %s: %s", lease.lease_id, exc)
        self.reaped += count
        return count


__all__ = ["LeaseReaper", "ReapableLease"]

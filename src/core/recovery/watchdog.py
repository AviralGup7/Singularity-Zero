"""Watchdog for auto-recovery triggers.

Checks leader lease, replication lag, stalled commitIndex, WAL fs, disk.
Rate-limited, never auto-enters survival on the first transient.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.core.recovery.survival import enter_survival, is_survival

logger = logging.getLogger(__name__)


@dataclass
class WatchdogProbe:
    leader_lease_ok: bool = True
    replication_lag_seconds: float = 0.0
    max_lag_seconds: float = 30.0
    commit_index: int = 0
    last_apply_mono: float = 0.0
    stall_seconds: float = 60.0
    wal_fs_ok: bool = True
    disk_free_ok: bool = True
    quorum: bool = True
    lkg_exists: bool = False


ProbeFn = Callable[[], WatchdogProbe]
ReconcileFn = Callable[[], Any]


@dataclass
class RecoveryWatchdog:
    probe: ProbeFn
    reconcile: ReconcileFn | None = None
    cooldown_seconds: float = 30.0
    max_attempts_per_hour: int = 12
    _last_fire_mono: float = field(default=0.0, init=False)
    _attempts: list[float] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    last_reason: str = field(default="", init=False)

    def check(self, *, now_mono: float | None = None) -> str | None:
        """Evaluate probes. Returns trigger reason or None."""
        now = time.monotonic() if now_mono is None else float(now_mono)
        try:
            snap = self.probe()
        except Exception as exc:
            logger.warning("Watchdog probe failed: %s", exc)
            return None

        reasons: list[str] = []
        if not snap.leader_lease_ok:
            reasons.append("leader_lease_expired")
        if snap.replication_lag_seconds > snap.max_lag_seconds:
            reasons.append("replication_lag")
        if snap.last_apply_mono and now - snap.last_apply_mono > snap.stall_seconds:
            reasons.append("commitIndex_stalled")
        if not snap.wal_fs_ok:
            reasons.append("wal_fs")
        if not snap.disk_free_ok:
            reasons.append("disk_free")
        if not snap.quorum:
            reasons.append("quorum_loss")
        if not reasons:
            return None

        reason = ",".join(reasons)
        with self._lock:
            if now - self._last_fire_mono < self.cooldown_seconds:
                return None
            hour_ago = now - 3600.0
            self._attempts = [t for t in self._attempts if t >= hour_ago]
            if len(self._attempts) >= self.max_attempts_per_hour:
                logger.warning("Watchdog suppressed (max attempts/hour): %s", reason)
                return None
            self._last_fire_mono = now
            self._attempts.append(now)
            self.last_reason = reason

        logger.warning("recovery.watchdog.trigger reason=%s", reason)
        if self.reconcile is not None and not is_survival():
            try:
                self.reconcile()
            except Exception as exc:
                logger.warning("Watchdog reconcile failed: %s", exc)

        if "wal_fs" in reasons or "quorum_loss" in reasons:
            if snap.lkg_exists:
                enter_survival(reason, commit_index=snap.commit_index)
        return reason


def env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


__all__ = ["RecoveryWatchdog", "WatchdogProbe", "env_flag"]

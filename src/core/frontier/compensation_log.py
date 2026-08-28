"""Durable CompensationLedger for exactly-once I28 lease compensation.

Crash window: a worker dies after marking COMPENSATING and before COMPENSATED.
Recovery re-enqueues only COMPENSATING rows whose timeout has elapsed.
CAS PENDING → COMPENSATING is exclusive; a second compensator is a no-op.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class CompensationStatus(StrEnum):
    PENDING = "PENDING"
    COMPENSATING = "COMPENSATING"
    COMPENSATED = "COMPENSATED"
    FAILED = "FAILED"


class CompensationConflict(RuntimeError):
    """Raised when a CAS transition is rejected (another worker owns the row)."""


@dataclass(slots=True)
class CompensationRecord:
    reservation_id: str
    lease_id: str
    status: CompensationStatus
    attempts: int = 0
    compensated_at: float | None = None
    reason: str = ""
    tx_id: str = ""
    updated_at_mono: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CompensationRecord:
        return cls(
            reservation_id=str(raw.get("reservation_id") or ""),
            lease_id=str(raw.get("lease_id") or ""),
            status=CompensationStatus(str(raw.get("status") or CompensationStatus.PENDING)),
            attempts=int(raw.get("attempts") or 0),
            compensated_at=(
                float(raw["compensated_at"]) if raw.get("compensated_at") is not None else None
            ),
            reason=str(raw.get("reason") or ""),
            tx_id=str(raw.get("tx_id") or ""),
            updated_at_mono=float(raw.get("updated_at_mono") or 0.0),
        )


def _key(reservation_id: str, lease_id: str) -> tuple[str, str]:
    return (str(reservation_id), str(lease_id))


class CompensationLedger:
    """In-process CAS ledger with optional JSONL durability."""

    def __init__(
        self,
        persist_path: Path | str | None = None,
        *,
        compensating_timeout_seconds: float = 30.0,
    ) -> None:
        self._lock = threading.RLock()
        self._rows: dict[tuple[str, str], CompensationRecord] = {}
        self._path = Path(persist_path) if persist_path is not None else None
        self.compensating_timeout_seconds = float(compensating_timeout_seconds)
        if self._path is not None:
            self._load()

    def get(self, reservation_id: str, lease_id: str) -> CompensationRecord | None:
        with self._lock:
            row = self._rows.get(_key(reservation_id, lease_id))
            return None if row is None else CompensationRecord.from_dict(row.to_dict())

    def ensure_pending(
        self, reservation_id: str, lease_id: str, *, reason: str = ""
    ) -> CompensationRecord:
        """Idempotently insert a PENDING row. Existing terminal rows are returned as-is."""
        with self._lock:
            key = _key(reservation_id, lease_id)
            existing = self._rows.get(key)
            if existing is not None:
                return existing
            row = CompensationRecord(
                reservation_id=str(reservation_id),
                lease_id=str(lease_id),
                status=CompensationStatus.PENDING,
                reason=reason,
                tx_id=uuid.uuid4().hex,
                updated_at_mono=time.monotonic(),
            )
            self._rows[key] = row
            self._persist_locked()
            return row

    def cas(
        self,
        reservation_id: str,
        lease_id: str,
        expected: CompensationStatus,
        target: CompensationStatus,
        *,
        reason: str = "",
    ) -> CompensationRecord:
        """Atomic status transition. Rejects if current status ≠ expected."""
        with self._lock:
            key = _key(reservation_id, lease_id)
            row = self._rows.get(key)
            if row is None:
                raise CompensationConflict(f"no compensation row for {reservation_id}/{lease_id}")
            if row.status != expected:
                raise CompensationConflict(
                    f"CAS failed {reservation_id}/{lease_id}: "
                    f"have {row.status.value} expected {expected.value}"
                )
            row.status = target
            row.attempts += 1
            row.updated_at_mono = time.monotonic()
            if reason:
                row.reason = reason
            if target is CompensationStatus.COMPENSATED:
                row.compensated_at = time.time()
            self._persist_locked()
            return row

    def compensate(
        self,
        reservation_id: str,
        lease_id: str,
        *,
        reason: str = "",
        release: Any | None = None,
    ) -> CompensationRecord:
        """Exactly-once compensation: PENDING→COMPENSATING then write COMPENSATED.

        ``release`` is an optional callable invoked while the row is COMPENSATING
        (the actual budget/lease mutation). If it raises, the row stays
        COMPENSATING for recovery replay. Duplicate calls on COMPENSATED are
        idempotent no-ops.
        """
        self.ensure_pending(reservation_id, lease_id, reason=reason)
        with self._lock:
            row = self._rows[_key(reservation_id, lease_id)]
            if row.status is CompensationStatus.COMPENSATED:
                return row
            if row.status is CompensationStatus.FAILED:
                row.status = CompensationStatus.PENDING
            if row.status is CompensationStatus.COMPENSATING:
                # Owned by an in-flight attempt; recovery will re-enqueue on timeout.
                return row
            row.status = CompensationStatus.COMPENSATING
            row.attempts += 1
            row.updated_at_mono = time.monotonic()
            if reason:
                row.reason = reason
            self._persist_locked()

        if release is not None:
            try:
                release(reservation_id, lease_id)
            except Exception:
                # Leave COMPENSATING so recover_inflight retries.
                raise

        return self.cas(
            reservation_id,
            lease_id,
            CompensationStatus.COMPENSATING,
            CompensationStatus.COMPENSATED,
            reason=reason,
        )

    def recover_inflight(self, *, now_mono: float | None = None) -> list[CompensationRecord]:
        """Rows stuck in COMPENSATING past the timeout — safe to retry."""
        now = time.monotonic() if now_mono is None else float(now_mono)
        stale: list[CompensationRecord] = []
        with self._lock:
            for row in self._rows.values():
                if row.status is not CompensationStatus.COMPENSATING:
                    continue
                if now - row.updated_at_mono >= self.compensating_timeout_seconds:
                    stale.append(row)
        return stale

    def replay_stale(self, *, release: Any | None = None) -> list[CompensationRecord]:
        """Reset timed-out COMPENSATING rows to PENDING and compensate again."""
        done: list[CompensationRecord] = []
        for row in self.recover_inflight():
            with self._lock:
                current = self._rows.get(_key(row.reservation_id, row.lease_id))
                if current is None or current.status is not CompensationStatus.COMPENSATING:
                    continue
                current.status = CompensationStatus.PENDING
                current.updated_at_mono = time.monotonic()
                self._persist_locked()
            done.append(
                self.compensate(
                    row.reservation_id,
                    row.lease_id,
                    reason=row.reason or "reaper_replay",
                    release=release,
                )
            )
        return done

    def _persist_locked(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = [row.to_dict() for row in self._rows.values()]
        tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._path)

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, list):
            return
        for item in raw:
            if not isinstance(item, dict):
                continue
            rec = CompensationRecord.from_dict(item)
            if rec.reservation_id and rec.lease_id:
                self._rows[_key(rec.reservation_id, rec.lease_id)] = rec


__all__ = [
    "CompensationConflict",
    "CompensationLedger",
    "CompensationRecord",
    "CompensationStatus",
]

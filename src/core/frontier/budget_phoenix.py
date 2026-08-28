"""Phoenix reconciliation: rebuild Outstanding/Consumed/Compensated from durable history.

On recovery, after FSM reconstruction, derive budget aggregates from
SettlementIntent, Outbox, CompensationLedger, and Lease rows. Ghost
outstanding reservations with evidence are compensated before READY.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.frontier.compensation_log import CompensationLedger, CompensationStatus
from src.core.frontier.lease_status import LeaseStatus, is_outstanding, normalize_lease_status

logger = logging.getLogger(__name__)

PHOENIX_ENV = "BUDGET_PHOENIX_ON_BOOT"
REPORT_ENV = "RECOVERY_WRITE_REPORT"


def phoenix_enabled() -> bool:
    raw = os.environ.get(PHOENIX_ENV, "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def write_report_enabled() -> bool:
    raw = os.environ.get(REPORT_ENV, "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


@dataclass
class PhoenixReport:
    outstanding: int = 0
    consumed: int = 0
    compensated: int = 0
    ghosts_compensated: list[str] = field(default_factory=list)
    orphans: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0
    chosen_snapshot: str = ""
    commit_index: int = 0
    state_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "outstanding": self.outstanding,
            "consumed": self.consumed,
            "compensated": self.compensated,
            "ghosts_compensated": list(self.ghosts_compensated),
            "orphans": list(self.orphans),
            "duration_ms": self.duration_ms,
            "chosen_snapshot": self.chosen_snapshot,
            "commitIndex": self.commit_index,
            "state_hash": self.state_hash,
        }


def _lease_status(item: Any) -> str:
    raw = getattr(item, "status", None)
    if raw is None and isinstance(item, dict):
        raw = item.get("status")
    return str(raw or "")


def _lease_ids(item: Any) -> tuple[str, str]:
    if isinstance(item, dict):
        return str(item.get("reservation_id") or item.get("sublease_id") or ""), str(
            item.get("lease_id") or item.get("sublease_id") or ""
        )
    return (
        str(getattr(item, "reservation_id", "") or getattr(item, "sublease_id", "") or ""),
        str(getattr(item, "lease_id", "") or getattr(item, "sublease_id", "") or ""),
    )


def reconcile_budget(
    *,
    leases: list[Any] | None = None,
    settlements: list[Any] | None = None,
    ledger: CompensationLedger | None = None,
    in_memory_outstanding: int | None = None,
    release: Any | None = None,
) -> PhoenixReport:
    """Derive budget from durable rows and compensate ghost outstanding."""
    started = time.perf_counter()
    report = PhoenixReport()
    if not phoenix_enabled():
        report.duration_ms = (time.perf_counter() - started) * 1000.0
        return report

    outstanding_ids: set[str] = set()
    consumed_ids: set[str] = set()
    compensated_ids: set[str] = set()

    for item in leases or []:
        try:
            status = normalize_lease_status(_lease_status(item))
        except ValueError:
            continue
        _res, lid = _lease_ids(item)
        ident = lid or _res
        if not ident:
            continue
        if status is LeaseStatus.CONSUMED:
            consumed_ids.add(ident)
        elif status is LeaseStatus.COMPENSATED:
            compensated_ids.add(ident)
        elif is_outstanding(status) or status is LeaseStatus.EXPIRED:
            outstanding_ids.add(ident)

    for item in settlements or []:
        status = ""
        ident = ""
        if isinstance(item, dict):
            status = str(item.get("status") or item.get("outcome") or "").upper()
            ident = str(item.get("lease_id") or item.get("execution_id") or "")
        else:
            status = str(getattr(item, "status", "") or "").upper()
            ident = str(getattr(item, "lease_id", "") or getattr(item, "execution_id", "") or "")
        if status in {"COMMITTED", "CONSUMED"} and ident:
            consumed_ids.add(ident)
            outstanding_ids.discard(ident)

    if ledger is not None:
        for row in list(getattr(ledger, "_rows", {}).values()):
            ident = row.lease_id or row.reservation_id
            if row.status is CompensationStatus.COMPENSATED:
                compensated_ids.add(ident)
                outstanding_ids.discard(ident)

    ghosts = sorted(outstanding_ids - consumed_ids - compensated_ids)
    if ledger is not None:
        for ident in ghosts:
            try:
                ledger.compensate(ident, ident, reason="phoenix_ghost_outstanding", release=release)
                report.ghosts_compensated.append(ident)
                compensated_ids.add(ident)
                outstanding_ids.discard(ident)
            except Exception as exc:
                logger.warning("Phoenix compensate %s failed: %s", ident, exc)
                report.orphans.append({"id": ident, "error": str(exc)})

    report.outstanding = len(outstanding_ids)
    report.consumed = len(consumed_ids)
    report.compensated = len(compensated_ids)
    if in_memory_outstanding is not None and in_memory_outstanding != report.outstanding:
        report.orphans.append(
            {
                "class": "IN_MEMORY_SKEW",
                "in_memory": in_memory_outstanding,
                "derived": report.outstanding,
            }
        )
    report.duration_ms = (time.perf_counter() - started) * 1000.0
    return report


def write_recovery_report(
    path: Path | str, report: PhoenixReport, extra: dict[str, Any] | None = None
) -> Path:
    """Write recovery_report.json before READY."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = report.to_dict()
    if extra:
        payload.update(extra)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    os.replace(tmp, dest)
    return dest


__all__ = [
    "PHOENIX_ENV",
    "PhoenixReport",
    "phoenix_enabled",
    "reconcile_budget",
    "write_recovery_report",
    "write_report_enabled",
]

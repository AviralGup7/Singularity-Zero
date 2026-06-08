"""Finding lifecycle state machine and per-stage SLA tracking.

The legacy ``SLATracker`` only measures remediation age from
``discovered_at``. In practice the full lifecycle is::

    OPEN  --(analyst acknowledges)-->  TRIAGED
    TRIAGED --(remediation starts)-->  IN_REMEDIATION
    IN_REMEDIATION --(fix merged)-->  FIXED
    FIXED --(analyst verifies)-->  VERIFIED
    any --(analyst marks)--> FALSE_POSITIVE
    any --(governance decides)--> ACCEPTED
    any --(reopened)--> OPEN

Each transition emits an ``SLAEvent`` row, and the manager exposes
per-stage lag metrics (``triage_lag_days``, ``remediation_days``,
``verification_days``) that the dashboard / GRC views consume.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class FindingState(StrEnum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    IN_REMEDIATION = "IN_REMEDIATION"
    FIXED = "FIXED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED = "ACCEPTED"
    REOPENED = "REOPENED"

    @classmethod
    def parse(cls, raw: Any) -> FindingState:
        if isinstance(raw, cls):
            return raw
        text = str(raw or "").strip().upper()
        for member in cls:
            if member.value == text:
                return member
        return cls.OPEN


# Allowed transitions, encoded once for consistency between producers
# and consumers. ``from -> set(to)``.
TRANSITIONS: dict[FindingState, set[FindingState]] = {
    FindingState.OPEN: {
        FindingState.TRIAGED,
        FindingState.FALSE_POSITIVE,
        FindingState.ACCEPTED,
        FindingState.IN_REMEDIATION,
    },
    FindingState.TRIAGED: {
        FindingState.IN_REMEDIATION,
        FindingState.FALSE_POSITIVE,
        FindingState.ACCEPTED,
        FindingState.OPEN,
    },
    FindingState.IN_REMEDIATION: {
        FindingState.FIXED,
        FindingState.OPEN,
        FindingState.FALSE_POSITIVE,
        FindingState.ACCEPTED,
    },
    FindingState.FIXED: {
        FindingState.VERIFIED,
        FindingState.REOPENED,
        FindingState.IN_REMEDIATION,
    },
    FindingState.VERIFIED: {FindingState.REOPENED},
    FindingState.FALSE_POSITIVE: {FindingState.REOPENED},
    FindingState.ACCEPTED: {FindingState.REOPENED, FindingState.OPEN},
    FindingState.REOPENED: {
        FindingState.TRIAGED,
        FindingState.IN_REMEDIATION,
        FindingState.FALSE_POSITIVE,
        FindingState.ACCEPTED,
    },
}


def can_transition(current: FindingState, target: FindingState) -> bool:
    return target in TRANSITIONS.get(current, set())


# Per-stage SLA targets, in days. Triage SLA is short because
# un-triaged findings are operational risk; remediation is
# severity-weighted via the legacy SLA tracker; verification is
# short because verification usually just means "rerun the test".
DEFAULT_TRIAGE_SLA_DAYS = 2.0
DEFAULT_VERIFICATION_SLA_DAYS = 5.0
DEFAULT_STAGE_TARGETS_DAYS: dict[str, float] = {
    "triage": DEFAULT_TRIAGE_SLA_DAYS,
    "remediation_critical": 14.0,
    "remediation_high": 30.0,
    "remediation_medium": 90.0,
    "verification": DEFAULT_VERIFICATION_SLA_DAYS,
}


@dataclass
class SLAEvent:
    """A single lifecycle transition for a finding."""

    event_id: str
    finding_id: str
    from_state: str
    to_state: str
    timestamp: float
    actor: str = ""
    note: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = f"sla_{uuid.uuid4().hex[:12]}"
        if not self.finding_id:
            raise ValueError("SLAEvent.finding_id is required")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SLAEvent:
        return cls(
            event_id=str(payload.get("event_id", "")),
            finding_id=str(payload.get("finding_id", "")),
            from_state=str(payload.get("from_state", "")),
            to_state=str(payload.get("to_state", "")),
            timestamp=float(payload.get("timestamp", time.time()) or time.time()),
            actor=str(payload.get("actor", "")),
            note=str(payload.get("note", "")),
            metadata=dict(payload.get("metadata", {}) or {}),
        )


@dataclass
class FindingLifecycleRecord:
    """The aggregated lifecycle state of a single finding."""

    finding_id: str
    current_state: FindingState = FindingState.OPEN
    discovered_at: float = field(default_factory=time.time)
    triaged_at: float = 0.0
    remediation_started_at: float = 0.0
    fixed_at: float = 0.0
    verified_at: float = 0.0
    events: list[SLAEvent] = field(default_factory=list)

    @property
    def triage_lag_days(self) -> float | None:
        if not self.triaged_at or not self.discovered_at:
            return None
        return max(0.0, (self.triaged_at - self.discovered_at) / 86400.0)

    @property
    def remediation_days(self) -> float | None:
        if not self.fixed_at or not self.remediation_started_at:
            return None
        return max(0.0, (self.fixed_at - self.remediation_started_at) / 86400.0)

    @property
    def verification_days(self) -> float | None:
        if not self.verified_at or not self.fixed_at:
            return None
        return max(0.0, (self.verified_at - self.fixed_at) / 86400.0)

    @property
    def total_open_days(self) -> float:
        end = self.verified_at or self.fixed_at or time.time()
        return max(0.0, (end - self.discovered_at) / 86400.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "current_state": self.current_state.value,
            "discovered_at": self.discovered_at,
            "triaged_at": self.triaged_at,
            "remediation_started_at": self.remediation_started_at,
            "fixed_at": self.fixed_at,
            "verified_at": self.verified_at,
            "triage_lag_days": _round(self.triage_lag_days),
            "remediation_days": _round(self.remediation_days),
            "verification_days": _round(self.verification_days),
            "total_open_days": _round(self.total_open_days),
            "events": [e.to_dict() for e in self.events],
        }


class FindingLifecycleManager:
    """Track per-finding lifecycle state and SLA events."""

    def __init__(self) -> None:
        self._records: dict[str, FindingLifecycleRecord] = {}

    # -- mutations -------------------------------------------------------

    def ensure(self, finding_id: str, *, discovered_at: float | None = None) -> FindingLifecycleRecord:
        record = self._records.get(finding_id)
        if record is None:
            record = FindingLifecycleRecord(
                finding_id=finding_id,
                discovered_at=float(discovered_at) if discovered_at else time.time(),
            )
            self._records[finding_id] = record
        return record

    def transition(
        self,
        finding_id: str,
        target: FindingState | str,
        *,
        actor: str = "",
        note: str = "",
        timestamp: float | None = None,
        force: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> FindingLifecycleRecord:
        record = self.ensure(finding_id)
        target_state = target if isinstance(target, FindingState) else FindingState.parse(target)
        if not force and not can_transition(record.current_state, target_state):
            raise ValueError(
                f"Illegal transition {record.current_state.value} -> {target_state.value} for {finding_id}"
            )
        ts = float(timestamp) if timestamp else time.time()
        record.events.append(
            SLAEvent(
                event_id="",
                finding_id=finding_id,
                from_state=record.current_state.value,
                to_state=target_state.value,
                timestamp=ts,
                actor=actor,
                note=note,
                metadata=dict(metadata or {}),
            )
        )
        record.current_state = target_state
        if target_state is FindingState.TRIAGED and not record.triaged_at:
            record.triaged_at = ts
        elif target_state is FindingState.IN_REMEDIATION and not record.remediation_started_at:
            record.remediation_started_at = ts
        elif target_state is FindingState.FIXED and not record.fixed_at:
            record.fixed_at = ts
        elif target_state is FindingState.VERIFIED and not record.verified_at:
            record.verified_at = ts
        return record

    def seed_from_finding(
        self,
        finding: dict[str, Any],
        *,
        events: Iterable[SLAEvent] | None = None,
    ) -> FindingLifecycleRecord:
        """Build a record from a finding dict.

        Looks for known timestamp fields (``discovered_at``,
        ``triaged_at``, ``remediation_started_at``, ``fixed_at``,
        ``verified_at``) and the ``lifecycle_state`` key.
        """
        finding_id = str(finding.get("id") or finding.get("finding_id") or "")
        if not finding_id:
            raise ValueError("seed_from_finding requires an id/finding_id")
        record = self.ensure(
            finding_id, discovered_at=_coerce_ts(finding.get("discovered_at"))
        )
        record.triaged_at = _coerce_ts(finding.get("triaged_at")) or record.triaged_at
        record.remediation_started_at = (
            _coerce_ts(finding.get("remediation_started_at")) or record.remediation_started_at
        )
        record.fixed_at = _coerce_ts(finding.get("fixed_at")) or record.fixed_at
        record.verified_at = _coerce_ts(finding.get("verified_at")) or record.verified_at
        if "lifecycle_state" in finding:
            record.current_state = FindingState.parse(finding.get("lifecycle_state"))
        for event in events or []:
            record.events.append(event)
        return record

    # -- accessors -------------------------------------------------------

    def get(self, finding_id: str) -> FindingLifecycleRecord | None:
        return self._records.get(finding_id)

    def all(self) -> list[FindingLifecycleRecord]:
        return list(self._records.values())

    # -- aggregation ----------------------------------------------------

    def summary(self) -> dict[str, Any]:
        states: dict[str, int] = {state.value: 0 for state in FindingState}
        triage_total = 0.0
        triage_count = 0
        remediation_total = 0.0
        remediation_count = 0
        verification_total = 0.0
        verification_count = 0
        for record in self._records.values():
            states[record.current_state.value] += 1
            if record.triage_lag_days is not None:
                triage_total += record.triage_lag_days
                triage_count += 1
            if record.remediation_days is not None:
                remediation_total += record.remediation_days
                remediation_count += 1
            if record.verification_days is not None:
                verification_total += record.verification_days
                verification_count += 1
        return {
            "total": len(self._records),
            "by_state": states,
            "avg_triage_lag_days": _round(triage_total / triage_count) if triage_count else 0.0,
            "avg_remediation_days": _round(
                remediation_total / remediation_count
            )
            if remediation_count
            else 0.0,
            "avg_verification_days": _round(
                verification_total / verification_count
            )
            if verification_count
            else 0.0,
            "sla_targets_days": dict(DEFAULT_STAGE_TARGETS_DAYS),
        }

    def breaches(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Return a list of lifecycle records that have breached a stage SLA."""
        now = now or time.time()
        targets = DEFAULT_STAGE_TARGETS_DAYS
        breached: list[dict[str, Any]] = []
        for record in self._records.values():
            triage_lag = record.triage_lag_days
            if (
                record.current_state is FindingState.OPEN
                and triage_lag is not None
                and triage_lag > targets["triage"]
            ):
                breached.append(
                    {
                        "finding_id": record.finding_id,
                        "stage": "triage",
                        "lag_days": triage_lag,
                        "target_days": targets["triage"],
                    }
                )
            if (
                record.current_state is FindingState.FIXED
                and record.verification_days is not None
                and record.verification_days > targets["verification"]
            ):
                breached.append(
                    {
                        "finding_id": record.finding_id,
                        "stage": "verification",
                        "lag_days": record.verification_days,
                        "target_days": targets["verification"],
                    }
                )
        return breached

    def lifecycle_summary(
        self,
        *,
        conn: Any | None = None,
        days: int = 30,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Aggregate per-stage SLA metrics over the given window.

        When ``conn`` is provided, the summary is derived from the
        ``sla_events`` table (one row per transition) so historical
        questions can be answered without re-walking in-memory
        records. When ``conn`` is None, falls back to the
        in-memory aggregation produced by :meth:`summary`.
        """
        targets = DEFAULT_STAGE_TARGETS_DAYS
        if conn is None:
            return self.summary()
        try:
            cutoff = (now or time.time()) - days * 86400.0
            cursor = conn.execute(
                "SELECT finding_id, from_state, to_state, timestamp "
                "FROM sla_events WHERE timestamp >= ? "
                "ORDER BY finding_id, timestamp",
                [cutoff],
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("lifecycle_summary: sla_events query failed: %s", exc)
            return self.summary()

        per_finding_events: dict[str, list[tuple[str, str, float]]] = {}
        for row in cursor.fetchall():
            per_finding_events.setdefault(row[0], []).append(
                (str(row[1] or ""), str(row[2] or ""), float(row[3] or 0.0))
            )

        triage_lags: list[float] = []
        remediation_lags: list[float] = []
        verification_lags: list[float] = []
        triage_breaches: list[dict[str, Any]] = []
        verification_breaches: list[dict[str, Any]] = []
        for finding_id, events in per_finding_events.items():
            triaged_ts: float | None = None
            discovered_ts: float | None = None
            remediation_ts: float | None = None
            fixed_ts: float | None = None
            verified_ts: float | None = None
            for _from, to, ts in events:
                if to == FindingState.OPEN.value and discovered_ts is None:
                    discovered_ts = ts
                if to == FindingState.TRIAGED.value and triaged_ts is None:
                    triaged_ts = ts
                if to == FindingState.IN_REMEDIATION.value and remediation_ts is None:
                    remediation_ts = ts
                if to == FindingState.FIXED.value and fixed_ts is None:
                    fixed_ts = ts
                if to == FindingState.VERIFIED.value and verified_ts is None:
                    verified_ts = ts

            if discovered_ts is not None and triaged_ts is not None:
                lag = max(0.0, (triaged_ts - discovered_ts) / 86400.0)
                triage_lags.append(lag)
                if lag > targets["triage"]:
                    triage_breaches.append(
                        {
                            "finding_id": finding_id,
                            "stage": "triage",
                            "lag_days": round(lag, 3),
                            "target_days": targets["triage"],
                        }
                    )

            if remediation_ts is not None and fixed_ts is not None:
                lag = max(0.0, (fixed_ts - remediation_ts) / 86400.0)
                remediation_lags.append(lag)
            if fixed_ts is not None and verified_ts is not None:
                lag = max(0.0, (verified_ts - fixed_ts) / 86400.0)
                verification_lags.append(lag)
                if lag > targets["verification"]:
                    verification_breaches.append(
                        {
                            "finding_id": finding_id,
                            "stage": "verification",
                            "lag_days": round(lag, 3),
                            "target_days": targets["verification"],
                        }
                    )

        def _avg(values: list[float]) -> float:
            return round(sum(values) / len(values), 3) if values else 0.0

        def _worst(values: list[float]) -> float:
            return round(max(values), 3) if values else 0.0

        return {
            "window_days": days,
            "sample_count": len(per_finding_events),
            "triage_lag_days": {
                "avg": _avg(triage_lags),
                "worst": _worst(triage_lags),
                "samples": len(triage_lags),
            },
            "remediation_days": {
                "avg": _avg(remediation_lags),
                "worst": _worst(remediation_lags),
                "samples": len(remediation_lags),
            },
            "verification_days": {
                "avg": _avg(verification_lags),
                "worst": _worst(verification_lags),
                "samples": len(verification_lags),
            },
            "breaches": {
                "triage": triage_breaches[:50],
                "verification": verification_breaches[:50],
                "triage_count": len(triage_breaches),
                "verification_count": len(verification_breaches),
            },
            "sla_targets_days": dict(targets),
        }


def _coerce_ts(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        import datetime

        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


__all__ = [
    "DEFAULT_STAGE_TARGETS_DAYS",
    "DEFAULT_TRIAGE_SLA_DAYS",
    "DEFAULT_VERIFICATION_SLA_DAYS",
    "FindingLifecycleManager",
    "FindingLifecycleRecord",
    "FindingState",
    "SLAEvent",
    "TRANSITIONS",
    "can_transition",
]

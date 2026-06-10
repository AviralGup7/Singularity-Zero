"""Risk acceptance model and management.

Risk acceptance is the act of formally carrying a known risk in
exchange for a documented justification, an accountable approver,
and a review date. Without it, accepted findings reappear in every
scan report and erode trust in the tool.

The on-disk shape of a ``RiskAcceptance``::

    {
      "acceptance_id": "acc_abc123",
      "finding_id": "f-...",
      "asset_id": "payment-processor",
      "accepted_until": 1735689600.0,   # unix seconds
      "accepted_by": "alice@example.com",
      "justification": "WAF rule #4711 blocks the SSRF externally.",
      "compensating_control_ref": "ctrl_xyz",
      "review_date": 1733097600.0,
      "scope": "global" | "asset" | "environment",
      "state": "active" | "expired" | "revoked",
      "created_at": 1730400000.0,
      "metadata": {...}
    }

Acceptances are evaluated at scoring time: an active acceptance
multiplies the residual finding score by 0 (suppress from active
queue) while still emitting it to audit history. Expired or
revoked acceptances have no effect.
"""

from __future__ import annotations

import copy
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

ACCEPTANCE_SCOPE_GLOBAL = "global"
ACCEPTANCE_SCOPE_ASSET = "asset"
ACCEPTANCE_SCOPE_ENVIRONMENT = "environment"

ACCEPTANCE_STATE_ACTIVE = "active"
ACCEPTANCE_STATE_EXPIRED = "expired"
ACCEPTANCE_STATE_REVOKED = "revoked"

ACCEPTANCE_SUPPRESSION_FACTOR = 0.0
ACCEPTANCE_EXPIRY_WARN_DAYS = 14


@dataclass
class RiskAcceptance:
    """A formal risk acceptance decision attached to a finding."""

    acceptance_id: str
    finding_id: str
    asset_id: str = ""
    accepted_until: float = 0.0
    accepted_by: str = ""
    justification: str = ""
    compensating_control_ref: str = ""
    review_date: float = 0.0
    scope: str = ACCEPTANCE_SCOPE_GLOBAL
    state: str = ACCEPTANCE_STATE_ACTIVE
    created_at: float = field(default_factory=time.time)
    created_by: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.acceptance_id:
            self.acceptance_id = f"acc_{uuid.uuid4().hex[:12]}"
        if not self.finding_id:
            raise ValueError("RiskAcceptance.finding_id is required")
        if self.scope not in {
            ACCEPTANCE_SCOPE_GLOBAL,
            ACCEPTANCE_SCOPE_ASSET,
            ACCEPTANCE_SCOPE_ENVIRONMENT,
        }:
            self.scope = ACCEPTANCE_SCOPE_GLOBAL
        if self.state not in {
            ACCEPTANCE_STATE_ACTIVE,
            ACCEPTANCE_STATE_EXPIRED,
            ACCEPTANCE_STATE_REVOKED,
        }:
            self.state = ACCEPTANCE_STATE_ACTIVE

    def is_active(self, now: float | None = None) -> bool:
        if self.state != ACCEPTANCE_STATE_ACTIVE:
            return False
        if not self.accepted_until:
            return True
        return (now or time.time()) < float(self.accepted_until)

    def days_until_expiry(self, now: float | None = None) -> float | None:
        if not self.accepted_until:
            return None
        return (float(self.accepted_until) - (now or time.time())) / 86400.0

    def is_expiry_warning(self, now: float | None = None) -> bool:
        delta = self.days_until_expiry(now=now)
        return delta is not None and 0 <= delta <= ACCEPTANCE_EXPIRY_WARN_DAYS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RiskAcceptance:
        return cls(
            acceptance_id=str(payload.get("acceptance_id", "")),
            finding_id=str(payload.get("finding_id", "")),
            asset_id=str(payload.get("asset_id", "")),
            accepted_until=float(payload.get("accepted_until", 0.0) or 0.0),
            accepted_by=str(payload.get("accepted_by", "")),
            justification=str(payload.get("justification", "")),
            compensating_control_ref=str(payload.get("compensating_control_ref", "")),
            review_date=float(payload.get("review_date", 0.0) or 0.0),
            scope=str(payload.get("scope", ACCEPTANCE_SCOPE_GLOBAL)),
            state=str(payload.get("state", ACCEPTANCE_STATE_ACTIVE)),
            created_at=float(payload.get("created_at", time.time()) or time.time()),
            created_by=str(payload.get("created_by", "")),
            metadata=dict(payload.get("metadata", {}) or {}),
        )


class RiskAcceptanceManager:
    """CRUD store + scoring-time evaluator for ``RiskAcceptance`` records."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: dict[str, RiskAcceptance] = {}
        self._by_finding: dict[str, list[str]] = {}

    # -- mutations -------------------------------------------------------

    def add(self, acceptance: RiskAcceptance) -> RiskAcceptance:
        with self._lock:
            # Remove any prior acceptance that shares the same finding + scope.
            self._purge_collisions(acceptance)
            self._by_id[acceptance.acceptance_id] = acceptance
            self._by_finding.setdefault(acceptance.finding_id, []).append(acceptance.acceptance_id)
        return acceptance

    def revoke(self, acceptance_id: str, *, reason: str = "") -> RiskAcceptance | None:
        with self._lock:
            acceptance = self._by_id.get(acceptance_id)
            if acceptance is None:
                return None
            acceptance.state = ACCEPTANCE_STATE_REVOKED
            if reason:
                acceptance.metadata["revoke_reason"] = reason
            acceptance.metadata.setdefault("revoked_at", time.time())
            return acceptance

    def remove(self, acceptance_id: str) -> bool:
        with self._lock:
            acceptance = self._by_id.pop(acceptance_id, None)
            if acceptance is None:
                return False
            bucket = self._by_finding.get(acceptance.finding_id, [])
            self._by_finding[acceptance.finding_id] = [
                aid for aid in bucket if aid != acceptance_id
            ]
            return True

    def _purge_collisions(self, candidate: RiskAcceptance) -> None:
        for aid in list(self._by_finding.get(candidate.finding_id, [])):
            existing = self._by_id.get(aid)
            if existing is None:
                continue
            if existing.scope == candidate.scope and existing.is_active():
                self.remove(aid)

    # -- accessors -------------------------------------------------------

    def get(self, acceptance_id: str) -> RiskAcceptance | None:
        with self._lock:
            return self._by_id.get(acceptance_id)

    def for_finding(self, finding_id: str) -> list[RiskAcceptance]:
        with self._lock:
            return [copy.copy(self._by_id[aid]) for aid in self._by_finding.get(finding_id, [])]

    def active_for_finding(
        self, finding_id: str, *, now: float | None = None
    ) -> list[RiskAcceptance]:
        return [a for a in self.for_finding(finding_id) if a.is_active(now=now)]

    def all(self) -> list[RiskAcceptance]:
        with self._lock:
            return list(self._by_id.values())

    def expiring_within(self, days: float, *, now: float | None = None) -> list[RiskAcceptance]:
        threshold = (now or time.time()) + days * 86400.0
        with self._lock:
            return [
                a
                for a in self._by_id.values()
                if a.is_active(now=now) and a.accepted_until and a.accepted_until <= threshold
            ]

    # -- scoring integration --------------------------------------------

    def suppression_factor(
        self,
        finding_id: str,
        *,
        now: float | None = None,
    ) -> float:
        """Return the multiplier to apply to a finding's residual score.

        Active acceptance -> 0.0 (suppress from active queue, retain in audit).
        Expired / revoked / no acceptance -> 1.0 (no effect).
        """
        active = self.active_for_finding(finding_id, now=now)
        if not active:
            return 1.0
        return ACCEPTANCE_SUPPRESSION_FACTOR

    def evaluate_finding(
        self, finding_id: str, *, now: float | None = None
    ) -> dict[str, Any]:
        acceptances = self.for_finding(finding_id)
        active = [a for a in acceptances if a.is_active(now=now)]
        return {
            "finding_id": finding_id,
            "acceptance_count": len(acceptances),
            "active_count": len(active),
            "suppressed": bool(active),
            "suppression_factor": self.suppression_factor(finding_id, now=now),
            "active_acceptances": [a.to_dict() for a in active],
        }

    # -- bulk load -------------------------------------------------------

    def load_from_dict(self, payload: dict[str, Any]) -> int:
        records = payload.get("acceptances", []) if isinstance(payload, dict) else payload
        if not isinstance(records, list):
            return 0
        loaded = 0
        for item in records:
            if not isinstance(item, dict):
                continue
            try:
                self.add(RiskAcceptance.from_dict(item))
                loaded += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("RiskAcceptance: skipping malformed record: %s", exc)
        return loaded

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"acceptances": [a.to_dict() for a in self._by_id.values()]}


# ---------------------------------------------------------------------------
# Module-level manager
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_manager: RiskAcceptanceManager | None = None


def get_default_acceptance_manager() -> RiskAcceptanceManager:
    global _default_manager
    with _default_lock:
        if _default_manager is None:
            _default_manager = RiskAcceptanceManager()
        return _default_manager


def reset_default_acceptance_manager() -> None:
    global _default_manager
    with _default_lock:
        _default_manager = None


__all__ = [
    "ACCEPTANCE_EXPIRY_WARN_DAYS",
    "ACCEPTANCE_SCOPE_ASSET",
    "ACCEPTANCE_SCOPE_ENVIRONMENT",
    "ACCEPTANCE_SCOPE_GLOBAL",
    "ACCEPTANCE_STATE_ACTIVE",
    "ACCEPTANCE_STATE_EXPIRED",
    "ACCEPTANCE_STATE_REVOKED",
    "ACCEPTANCE_SUPPRESSION_FACTOR",
    "RiskAcceptance",
    "RiskAcceptanceManager",
    "get_default_acceptance_manager",
    "reset_default_acceptance_manager",
]

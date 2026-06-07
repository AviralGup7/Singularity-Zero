"""Compensating control tracking and discount engine.

Compensating controls (WAF rules, IP allow-listing, MFA, network
segmentation, ...) reduce residual risk even when a vulnerability
is present. This module:

* Defines a small vocabulary of control types with default discount
  factors.
* Tracks per-finding ``CompensatingControl`` records.
* Computes a combined ``control_discount`` factor (0.0 - 1.0) that
  callers multiply against raw severity to obtain residual score.

The defaults are deliberately conservative (WAF = 0.5 means "halves
the residual score for a blocked exploit"). Override per-control
through configuration or the API.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Default discount per control type. Lower = stronger mitigation.
# 1.0 = no effect; 0.0 = fully mitigated.
DEFAULT_CONTROL_DISCOUNTS: dict[str, float] = {
    "waf": 0.55,
    "ips": 0.6,
    "rate_limiting": 0.7,
    "network_segmentation": 0.5,
    "mfa": 0.65,
    "ip_allow_list": 0.55,
    "auth_required": 0.7,
    "input_validation": 0.6,
    "output_encoding": 0.6,
    "csrf_token": 0.7,
    "csp": 0.65,
    "encrypted_at_rest": 0.5,
    "encrypted_in_transit": 0.55,
    "siem_alerting": 0.85,
    "patch_pending": 0.95,
    "compensating_policy": 0.8,
}

# Order matters: more specific control types should be checked first.
ALL_CONTROL_TYPES: tuple[str, ...] = (
    "waf",
    "ips",
    "rate_limiting",
    "network_segmentation",
    "mfa",
    "ip_allow_list",
    "auth_required",
    "input_validation",
    "output_encoding",
    "csrf_token",
    "csp",
    "encrypted_at_rest",
    "encrypted_in_transit",
    "siem_alerting",
    "patch_pending",
    "compensating_policy",
)


@dataclass
class CompensatingControl:
    """A single compensating control attached to a finding."""

    control_id: str
    finding_id: str
    control_type: str
    description: str = ""
    discount_factor: float = 0.85
    evidence_url: str = ""
    owner: str = ""
    expires_at: float = 0.0
    active: bool = True
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.control_id:
            self.control_id = f"ctrl_{uuid.uuid4().hex[:12]}"
        if not self.finding_id:
            raise ValueError("CompensatingControl.finding_id is required")
        if self.control_type not in ALL_CONTROL_TYPES:
            logger.debug(
                "CompensatingControl: unknown control_type %r - storing verbatim",
                self.control_type,
            )
        self.discount_factor = _clamp(self.discount_factor, 0.0, 1.0)

    def is_expired(self, now: float | None = None) -> bool:
        if not self.expires_at:
            return False
        return (now or time.time()) >= float(self.expires_at)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> CompensatingControl:
        return cls(
            control_id=str(payload.get("control_id", "")),
            finding_id=str(payload.get("finding_id", "")),
            control_type=str(payload.get("control_type", "compensating_policy")),
            description=str(payload.get("description", "")),
            discount_factor=float(payload.get("discount_factor", 0.85) or 0.85),
            evidence_url=str(payload.get("evidence_url", "")),
            owner=str(payload.get("owner", "")),
            expires_at=float(payload.get("expires_at", 0.0) or 0.0),
            active=bool(payload.get("active", True)),
            created_at=float(payload.get("created_at", time.time()) or time.time()),
            metadata=dict(payload.get("metadata", {}) or {}),
        )


class CompensatingControlEngine:
    """Combine multiple controls for a finding into a single discount.

    Multiple stacking controls compose multiplicatively (e.g. WAF
    at 0.55 and MFA at 0.65 yields a combined discount of
    0.55 * 0.65 = 0.3575), with a floor of 0.05 to keep *some*
    residual risk visible to analysts.
    """

    DISCOUNT_FLOOR = 0.05

    def __init__(self, base_discounts: dict[str, float] | None = None) -> None:
        self.base_discounts = dict(base_discounts or DEFAULT_CONTROL_DISCOUNTS)
        self._lock = threading.RLock()
        self._by_finding: dict[str, list[CompensatingControl]] = {}

    # -- registry --------------------------------------------------------

    def register(self, control: CompensatingControl) -> CompensatingControl:
        if control.control_type in self.base_discounts and not control.discount_factor:
            control.discount_factor = self.base_discounts[control.control_type]
        with self._lock:
            self._by_finding.setdefault(control.finding_id, []).append(control)
        return control

    def register_many(self, controls: Iterable[CompensatingControl]) -> list[CompensatingControl]:
        return [self.register(c) for c in controls]

    def remove(self, control_id: str) -> bool:
        with self._lock:
            for finding_id, controls in self._by_finding.items():
                kept = [c for c in controls if c.control_id != control_id]
                if len(kept) != len(controls):
                    self._by_finding[finding_id] = kept
                    return True
        return False

    def for_finding(self, finding_id: str) -> list[CompensatingControl]:
        with self._lock:
            return list(self._by_finding.get(finding_id, []))

    # -- discount computation -------------------------------------------

    def combined_discount(
        self, finding_id: str, *, now: float | None = None
    ) -> float:
        """Return the combined discount factor (0.0 - 1.0) for a finding."""
        controls = [
            c
            for c in self.for_finding(finding_id)
            if c.active and not c.is_expired(now)
        ]
        if not controls:
            return 1.0
        combined = 1.0
        for control in controls:
            factor = _clamp(control.discount_factor, 0.0, 1.0)
            combined *= factor
        return _clamp(combined, self.DISCOUNT_FLOOR, 1.0)

    def apply_to_score(self, finding_id: str, raw_score: float, *, now: float | None = None) -> float:
        return float(raw_score) * self.combined_discount(finding_id, now=now)

    def breakdown(self, finding_id: str, *, now: float | None = None) -> dict[str, Any]:
        """Return a serialisable description of how a discount was computed."""
        active = [c for c in self.for_finding(finding_id) if c.active and not c.is_expired(now)]
        return {
            "finding_id": finding_id,
            "control_count": len(active),
            "controls": [c.to_dict() for c in active],
            "combined_discount": self.combined_discount(finding_id, now=now),
        }

    # -- bulk load -------------------------------------------------------

    def load_from_dict(self, payload: dict[str, Any]) -> int:
        records = payload.get("controls", []) if isinstance(payload, dict) else payload
        if not isinstance(records, list):
            return 0
        loaded = 0
        for item in records:
            if not isinstance(item, dict):
                continue
            try:
                self.register(CompensatingControl.from_dict(item))
                loaded += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("CompensatingControl: skipping malformed control: %s", exc)
        return loaded

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            controls = [c for cs in self._by_finding.values() for c in cs]
        return {"controls": [c.to_dict() for c in controls]}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))


# ---------------------------------------------------------------------------
# Module-level default engine
# ---------------------------------------------------------------------------

_default_engine_lock = threading.Lock()
_default_engine: CompensatingControlEngine | None = None


def get_default_control_engine() -> CompensatingControlEngine:
    global _default_engine
    with _default_engine_lock:
        if _default_engine is None:
            _default_engine = CompensatingControlEngine()
        return _default_engine


def reset_default_control_engine() -> None:
    global _default_engine
    with _default_engine_lock:
        _default_engine = None


__all__ = [
    "ALL_CONTROL_TYPES",
    "CompensatingControl",
    "CompensatingControlEngine",
    "DEFAULT_CONTROL_DISCOUNTS",
    "get_default_control_engine",
    "reset_default_control_engine",
]

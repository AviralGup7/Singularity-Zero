"""Canonical lease / sub-lease lifecycle (Invariant I28).

Legal transitions:

    (absent) ──reserve──► RESERVED ──allocate──► ACTIVE ──settle(consumed>0)──► CONSUMED
                             │                      │
                             ├──expire──────────────┴──► EXPIRED
                             ├──compensate────────────────────────► COMPENSATED
                             └──settle(consumed>0)────────────────► CONSUMED
    EXPIRED ──compensate──► COMPENSATED

COMPENSATED is permitted only from RESERVED or EXPIRED. ACTIVE cannot compensate. Duplicate compensation
is an idempotent no-op. Legacy aliases (ISSUED, CLOSED, SETTLEMENT_PENDING,
REQUESTED) are normalized on read.
"""

from __future__ import annotations

from enum import StrEnum


class LeaseStatus(StrEnum):
    RESERVED = "RESERVED"
    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    COMPENSATED = "COMPENSATED"


_ALIASES: dict[str, LeaseStatus] = {
    "RESERVED": LeaseStatus.RESERVED,
    "ISSUED": LeaseStatus.RESERVED,
    "REQUESTED": LeaseStatus.RESERVED,
    "ACTIVE": LeaseStatus.ACTIVE,
    "SETTLEMENT_PENDING": LeaseStatus.ACTIVE,
    "CONSUMED": LeaseStatus.CONSUMED,
    "CLOSED": LeaseStatus.CONSUMED,
    "EXPIRED": LeaseStatus.EXPIRED,
    "COMPENSATED": LeaseStatus.COMPENSATED,
}

OUTSTANDING: frozenset[LeaseStatus] = frozenset({LeaseStatus.RESERVED, LeaseStatus.ACTIVE})
TERMINAL: frozenset[LeaseStatus] = frozenset(
    {LeaseStatus.CONSUMED, LeaseStatus.EXPIRED, LeaseStatus.COMPENSATED}
)

_LEGAL: dict[LeaseStatus, frozenset[LeaseStatus]] = {
    LeaseStatus.RESERVED: frozenset(
        {LeaseStatus.ACTIVE, LeaseStatus.EXPIRED, LeaseStatus.COMPENSATED, LeaseStatus.CONSUMED}
    ),
    LeaseStatus.ACTIVE: frozenset({LeaseStatus.CONSUMED, LeaseStatus.EXPIRED, LeaseStatus.ACTIVE}),
    LeaseStatus.EXPIRED: frozenset({LeaseStatus.COMPENSATED, LeaseStatus.EXPIRED}),
    LeaseStatus.CONSUMED: frozenset({LeaseStatus.CONSUMED}),
    LeaseStatus.COMPENSATED: frozenset({LeaseStatus.COMPENSATED}),
}


def normalize_lease_status(raw: str | LeaseStatus | None) -> LeaseStatus:
    """Map any stored status string onto the canonical enum."""
    if isinstance(raw, LeaseStatus):
        return raw
    key = str(raw or "").strip().upper()
    if key in _ALIASES:
        return _ALIASES[key]
    raise ValueError(f"Unknown lease status {raw!r}")


def is_outstanding(raw: str | LeaseStatus | None) -> bool:
    try:
        return normalize_lease_status(raw) in OUTSTANDING
    except ValueError:
        return False


def is_terminal(raw: str | LeaseStatus | None) -> bool:
    try:
        return normalize_lease_status(raw) in TERMINAL
    except ValueError:
        return False


def can_transition(current: str | LeaseStatus, target: str | LeaseStatus) -> bool:
    src = normalize_lease_status(current)
    dst = normalize_lease_status(target)
    if src == dst:
        return True
    return dst in _LEGAL.get(src, frozenset())


def require_transition(current: str | LeaseStatus, target: str | LeaseStatus) -> LeaseStatus:
    """Return canonical target status or raise on illegal I28 transition."""
    src = normalize_lease_status(current)
    dst = normalize_lease_status(target)
    if not can_transition(src, dst):
        raise ValueError(f"Illegal lease transition (I28): {src.value} -> {dst.value}")
    return dst

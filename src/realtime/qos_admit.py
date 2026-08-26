"""Single QoS admission function (F-009).

Architecture: ≥85% disk sheds P4; ≥92% sheds P3 and P4. The broker and
tests both call ``qos_admit`` so the chart names a function, not a magic
number on an unlabeled arrow.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from src.realtime.prioritized_broker import QoSClass

DISK_BACKPRESSURE_PCT = 85.0
DISK_EMERGENCY_PCT = 92.0


class QoSDecision(StrEnum):
    ADMIT = "admit"
    COALESCE = "coalesce"
    DROP = "drop"


def _qos_of(event: Any) -> QoSClass:
    if isinstance(event, QoSClass):
        return event
    qos = getattr(event, "qos", event)
    if isinstance(qos, QoSClass):
        return qos
    return QoSClass(int(qos))


def qos_admit(
    event: Any,
    disk_pct: float,
    *,
    backpressure_pct: float = DISK_BACKPRESSURE_PCT,
    emergency_pct: float = DISK_EMERGENCY_PCT,
) -> QoSDecision:
    """Return admit | coalesce | drop for one event under disk pressure."""
    qos = _qos_of(event)
    pct = float(disk_pct)
    if pct >= float(emergency_pct):
        if qos in {QoSClass.P3_TELEMETRY, QoSClass.P4_DEBUG}:
            return QoSDecision.DROP
        if qos in {QoSClass.P1_LIFECYCLE, QoSClass.P2_FINDINGS}:
            return QoSDecision.COALESCE
        return QoSDecision.ADMIT
    if pct >= float(backpressure_pct) and qos is QoSClass.P4_DEBUG:
        return QoSDecision.DROP
    return QoSDecision.ADMIT


__all__ = [
    "DISK_BACKPRESSURE_PCT",
    "DISK_EMERGENCY_PCT",
    "QoSDecision",
    "qos_admit",
]

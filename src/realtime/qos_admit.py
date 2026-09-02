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
    ram_pct: float = 0.0,
    cpu_pct: float = 0.0,
    spool_depth: int = 0,
    backpressure_pct: float = DISK_BACKPRESSURE_PCT,
    emergency_pct: float = DISK_EMERGENCY_PCT,
) -> QoSDecision:
    """Return admit | coalesce | drop for an event under multi-dimensional QoS pressure (F-009)."""
    qos = _qos_of(event)
    d_pct = float(disk_pct)
    r_pct = float(ram_pct)
    c_pct = float(cpu_pct)
    s_depth = int(spool_depth)

    # 1. Spool saturation check (> 1000 items)
    if s_depth > 1000:
        if int(qos) == 0:
            return QoSDecision.ADMIT
        return QoSDecision.DROP

    # 2. Severe resource pressure (>= 92% Disk or > 90% RAM)
    if d_pct >= float(emergency_pct) or r_pct > 90.0:
        if qos in {QoSClass.P3_TELEMETRY, QoSClass.P4_DEBUG}:
            return QoSDecision.DROP
        if qos in {QoSClass.P1_LIFECYCLE, QoSClass.P2_FINDINGS}:
            return QoSDecision.COALESCE
        return QoSDecision.ADMIT

    # 3. Moderate resource pressure (>= 85% Disk or > 90% CPU)
    if (d_pct >= float(backpressure_pct) or c_pct > 90.0) and qos is QoSClass.P4_DEBUG:
        return QoSDecision.DROP

    return QoSDecision.ADMIT


__all__ = [
    "DISK_BACKPRESSURE_PCT",
    "DISK_EMERGENCY_PCT",
    "QoSDecision",
    "qos_admit",
]

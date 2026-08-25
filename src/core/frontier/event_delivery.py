"""Authoritative event → durable outbox → EventBus dispatcher (I31 / I32).

EventBus is an in-process notification mechanism. It is not a durable
log and not a source of truth. Failure to deliver on the bus must not
roll back settlement (I32).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from src.core.contracts.command_envelope import EventEnvelope
from src.core.frontier.global_invariants import (
    I32_EVENTBUS_NON_AUTHORITY,
    assert_settlement_causality,
)

logger = logging.getLogger(__name__)


def _finding_event_envelope(
    *,
    finding: Mapping[str, Any],
    settle_res: Any,
    stage_name: str,
    sequence: int,
) -> EventEnvelope:
    wal_id = str(getattr(settle_res, "wal_id", "") or "")
    exec_id = str(getattr(settle_res, "execution_id", "") or stage_name)
    event_id = EventEnvelope.derive_event_id(f"settlement:{stage_name}", sequence, sequence)
    return EventEnvelope(
        event_id=event_id,
        event_type="FINDING_CREATED",
        aggregate_id=exec_id,
        aggregate_version=1,
        payload={
            "finding": dict(finding),
            "wal_id": wal_id,
            "execution_id": exec_id,
            "authoritative": True,
            "stage_name": stage_name,
        },
        correlation_id=exec_id,
        causation_id=wal_id,
        partition_id="P-0000",
    )


def dispatch_committed_findings(
    *,
    settle_res: Any,
    stage_name: str,
    findings: Sequence[Any],
    emit: Callable[..., Any],
    event_type: Any,
    outbox: Any | None = None,
    trace_id: str = "",
) -> int:
    """Publish FINDING_CREATED only after durable settlement (I31).

    Order: assert causality → append DurableOutbox → EventBus notify.
    Outbox or bus failures are logged; they do not un-commit settlement (I32).
    """
    assert_settlement_causality(settle_res)
    published = 0
    envelopes: list[EventEnvelope] = []
    dict_findings: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, Mapping) or isinstance(item, (str, bytes)):
            continue
        finding = dict(item)
        dict_findings.append(finding)
        envelopes.append(
            _finding_event_envelope(
                finding=finding,
                settle_res=settle_res,
                stage_name=stage_name,
                sequence=published,
            )
        )
        published += 1

    if outbox is not None and envelopes:
        try:
            outbox.append_events(envelopes)
        except Exception as exc:
            logger.warning(
                "%s: durable outbox append failed after COMMITTED settlement "
                "(authoritative state unchanged): %s",
                I32_EVENTBUS_NON_AUTHORITY,
                exc,
            )

    wal_id = getattr(settle_res, "wal_id", None)
    exec_id = getattr(settle_res, "execution_id", "")
    for envelope, finding in zip(envelopes, dict_findings, strict=True):
        try:
            emit(
                event_type,
                source=f"settlement.{stage_name}",
                data={
                    "finding": finding,
                    "trace_id": trace_id,
                    "wal_id": wal_id,
                    "execution_id": exec_id,
                    "event_id": envelope.event_id,
                    "causation_id": envelope.causation_id,
                    "authoritative": True,
                },
                trace_id=trace_id or None,
            )
        except Exception as exc:
            logger.warning(
                "%s: EventBus delivery failed after COMMITTED settlement "
                "(authoritative state unchanged): %s",
                I32_EVENTBUS_NON_AUTHORITY,
                exc,
            )
    return published


__all__ = [
    "dispatch_committed_findings",
]

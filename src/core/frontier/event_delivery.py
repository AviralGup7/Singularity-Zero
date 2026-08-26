"""Authoritative event → durable outbox → EventBus dispatcher (I31 / I32 / I33).

EventBus is an in-process notification mechanism. It is not a durable
log and not a source of truth. Failure to deliver on the bus must not
roll back settlement (I32).

Delivery identity (I33): EventId is derived from WalId; DeliveryId is
derived from EventId. Replaying dispatch after a crash reuses the same
ids so outbox and consumers can dedupe.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from src.core.contracts.command_envelope import EventEnvelope
from src.core.frontier.causal_identity import (
    CausalIdentity,
    derive_delivery_id,
    derive_event_id_from_wal,
    mint_causal_identity,
)
from src.core.frontier.failure_model import FailureClass, must_not
from src.core.frontier.global_invariants import (
    I32_EVENTBUS_NON_AUTHORITY,
    assert_settlement_causality,
)

logger = logging.getLogger(__name__)


class DeliveryLedger:
    """In-process exactly-once record of EventBus deliveries (I33 DeliveryId)."""

    def __init__(self) -> None:
        self._delivered: set[str] = set()
        self._lock = threading.Lock()

    def already_delivered(self, delivery_id: str) -> bool:
        did = str(delivery_id or "").strip()
        if not did:
            return False
        with self._lock:
            return did in self._delivered

    def record(self, delivery_id: str) -> bool:
        """Record a successful delivery. True if this was the first time."""
        did = str(delivery_id or "").strip()
        if not did:
            return False
        with self._lock:
            if did in self._delivered:
                return False
            self._delivered.add(did)
            return True

    def clear(self) -> None:
        with self._lock:
            self._delivered.clear()

    def delivered_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._delivered)

    def discard_unknown(self, allowed_delivery_ids: Sequence[str]) -> int:
        """Drop DeliveryIds that are not in the outbox-derived allowlist (I35)."""
        allowed = {str(item).strip() for item in allowed_delivery_ids if str(item or "").strip()}
        with self._lock:
            unknown = self._delivered - allowed
            if not unknown:
                return 0
            self._delivered -= unknown
            return len(unknown)


_delivery_ledger = DeliveryLedger()


def get_delivery_ledger() -> DeliveryLedger:
    return _delivery_ledger


def reset_delivery_ledger() -> None:
    _delivery_ledger.clear()


def _identity_from_settle(settle_res: Any, stage_name: str) -> CausalIdentity:
    exec_id = str(getattr(settle_res, "execution_id", "") or stage_name)
    wal_id = str(getattr(settle_res, "wal_id", "") or "")
    return mint_causal_identity(
        execution_id=exec_id,
        command_id=str(getattr(settle_res, "command_id", "") or ""),
        attempt_id=str(getattr(settle_res, "attempt_id", "") or ""),
        settlement_id=str(getattr(settle_res, "settlement_id", "") or ""),
        wal_id=wal_id,
    )


def _finding_event_envelope(
    *,
    finding: Mapping[str, Any],
    identity: CausalIdentity,
    stage_name: str,
    sequence: int,
) -> EventEnvelope:
    wal_id = identity.wal_id
    event_id = derive_event_id_from_wal(wal_id, sequence)
    bound = identity.with_event(event_id).with_delivery(derive_delivery_id(event_id, 1))
    return EventEnvelope(
        event_id=event_id,
        event_type="FINDING_CREATED",
        aggregate_id=identity.execution_id,
        aggregate_version=1,
        payload={
            "finding": dict(finding),
            **bound.payload_fields(),
            "stage_name": stage_name,
        },
        correlation_id=identity.command_id or identity.execution_id,
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
    delivery_ledger: DeliveryLedger | None = None,
) -> int:
    """Publish FINDING_CREATED only after durable settlement (I31).

    Order: assert causality → append DurableOutbox → EventBus notify.
    Outbox or bus failures are logged; they do not un-commit settlement (I32).
    Duplicate DeliveryId is skipped so crash-replay of dispatch is a no-op (I33).
    """
    assert_settlement_causality(settle_res)
    identity = _identity_from_settle(settle_res, stage_name)
    ledger = delivery_ledger if delivery_ledger is not None else get_delivery_ledger()
    if outbox is not None and hasattr(outbox, "read_all_events"):
        try:
            existing = outbox.read_all_events()
            reconcile_delivery_against_outbox(
                ledger, [str(getattr(evt, "event_id", "") or "") for evt in existing]
            )
        except Exception:  # noqa: BLE001
            logger.debug("I35 delivery/outbox reconcile skipped", exc_info=True)
    published = 0
    envelopes: list[EventEnvelope] = []
    dict_findings: list[dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, Mapping) or isinstance(item, (str, bytes)):
            continue
        finding = dict(item)
        event_id = derive_event_id_from_wal(identity.wal_id, published)
        finding.setdefault("event_id", event_id)
        dict_findings.append(finding)
        envelopes.append(
            _finding_event_envelope(
                finding=finding,
                identity=identity,
                stage_name=stage_name,
                sequence=published,
            )
        )
        published += 1

    outbox_ok = True
    if outbox is not None and envelopes:
        try:
            outbox.append_events(envelopes)
        except Exception as exc:
            must_not(FailureClass.EVENT_DELIVERY_FAILURE, "rollback")
            outbox_ok = False
            logger.warning(
                "%s: durable outbox append failed after COMMITTED settlement "
                "(authoritative state unchanged; bus will not notify; "
                "replay rebuilds outbox then bus): %s",
                I32_EVENTBUS_NON_AUTHORITY,
                exc,
            )

    if not outbox_ok:
        # I31 order is WAL → outbox → bus. Do not notify consumers of a
        # finding that is not in the outbox.
        return published

    from src.core.frontier.settlement_receipt import stamp_finding_receipt

    receipt = stamp_finding_receipt(
        wal_id=str(getattr(settle_res, "wal_id", "") or ""),
        settlement_id=str(getattr(settle_res, "settlement_id", "") or identity.settlement_id),
        command_id=str(getattr(settle_res, "command_id", "") or identity.command_id),
        status="COMMITTED",
    )

    for envelope, finding in zip(envelopes, dict_findings, strict=True):
        event_id = envelope.event_id
        delivery_id = derive_delivery_id(event_id, 1)
        if ledger.already_delivered(delivery_id):
            continue
        bound = identity.with_event(event_id).with_delivery(delivery_id)
        try:
            emit(
                event_type,
                source=f"settlement.{stage_name}",
                data={
                    "finding": finding,
                    "trace_id": trace_id,
                    **bound.payload_fields(),
                    **receipt,
                    "causation_id": envelope.causation_id,
                },
                trace_id=trace_id or None,
            )
            ledger.record(delivery_id)
        except Exception as exc:
            must_not(FailureClass.EVENT_DELIVERY_FAILURE, "rollback")
            logger.warning(
                "%s: EventBus delivery failed after COMMITTED settlement "
                "(authoritative state unchanged; retry allowed, no compensate): %s",
                I32_EVENTBUS_NON_AUTHORITY,
                exc,
            )
    return published


def reconcile_delivery_against_outbox(
    ledger: DeliveryLedger,
    outbox_event_ids: Sequence[str],
) -> int:
    """I35: delivery ahead of outbox is a cache bug — discard extras.

    Returns the number of DeliveryIds removed. Missing deliveries are
    left unrecorded so the next ``dispatch_committed_findings`` replays.
    """
    allowed = [derive_delivery_id(str(event_id), 1) for event_id in outbox_event_ids if event_id]
    return ledger.discard_unknown(allowed)


__all__ = [
    "DeliveryLedger",
    "dispatch_committed_findings",
    "get_delivery_ledger",
    "reconcile_delivery_against_outbox",
    "reset_delivery_ledger",
]

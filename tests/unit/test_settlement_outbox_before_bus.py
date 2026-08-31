"""I31: durable outbox append is bound to settlement before EventBus notify."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any


class _MemOutbox:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def append_events(self, events, sync: bool = True) -> int:
        self.events.extend(list(events))
        return len(list(events))

    def read_all_events(self):
        return list(self.events)


def test_append_outbox_for_intent_under_coordinator():
    from src.core.frontier.state_authority import (
        SettlementCoordinator,
        SettlementIntent,
        StateAuthority,
    )

    sa = StateAuthority(wal=None)
    outbox = _MemOutbox()
    coord = SettlementCoordinator(state_authority=sa, outbox=outbox)
    intent = SettlementIntent(
        settlement_id="stl1",
        execution_id="e1",
        outcome="COMPLETED",
        outbox_intent=True,
        stage_name="scan",
    )
    findings = ({"title": "x", "severity": "high"},)
    ok, event_ids = coord._append_outbox_for_intent(intent, "wal-1", findings)
    assert ok is True
    assert len(event_ids) == 1
    assert len(outbox.events) == 1
    assert outbox.events[0].payload["wal_id"] == "wal-1"


def test_dispatch_refuses_bus_when_outbox_not_appended():
    from src.core.frontier.event_delivery import dispatch_committed_findings, reset_delivery_ledger

    reset_delivery_ledger()
    emitted: list[dict] = []

    def emit(event_type, **kwargs):
        emitted.append(kwargs.get("data") or {})

    settle_res = SimpleNamespace(
        execution_id="e1",
        wal_id="wal-abc",
        command_id="cmd1",
        attempt_id="att1",
        settlement_id="stl1",
        status="COMMITTED",
        outbox_intent=True,
        outbox_appended=False,
    )
    n = dispatch_committed_findings(
        settle_res=settle_res,
        stage_name="scan",
        findings=[{"title": "f1"}],
        emit=emit,
        event_type="finding_created",
        outbox=None,
    )
    assert n >= 0
    assert emitted == []


def test_dispatch_skips_reappend_when_settlement_outbox_done():
    from src.core.frontier.event_delivery import dispatch_committed_findings, reset_delivery_ledger
    from src.core.frontier.settlement_receipt import stamp_finding_receipt

    reset_delivery_ledger()
    outbox = _MemOutbox()
    emitted: list[dict] = []

    def emit(event_type, **kwargs):
        emitted.append(kwargs.get("data") or {})

    wal_id = "wal-xyz"
    receipt = stamp_finding_receipt(
        wal_id=wal_id, settlement_id="stl1", command_id="cmd1", status="COMMITTED"
    )
    fields = {
        "execution_id": "e1",
        "attempt_id": "att1",
        "outbox_intent": True,
        "outbox_appended": True,
    }
    fields.update(receipt)
    settle_res = SimpleNamespace(**fields)
    n = dispatch_committed_findings(
        settle_res=settle_res,
        stage_name="scan",
        findings=[{"title": "f1"}],
        emit=emit,
        event_type="finding_created",
        outbox=outbox,
    )
    assert outbox.events == []
    assert n >= 1

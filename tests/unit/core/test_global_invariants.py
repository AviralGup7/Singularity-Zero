"""I30 authorization causality, I31 settlement causality, I32 EventBus non-authority."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.core.frontier.event_delivery import dispatch_committed_findings, reset_delivery_ledger
from src.core.frontier.global_invariants import (
    AuthorizationCausalityError,
    SettlementCausalityError,
    assert_authorization_causality,
    assert_settlement_causality,
)
from src.core.frontier.outbox import DurableOutboxLedger
from src.core.frontier.state_authority import SettlementResult
from src.decision.authorization import AuthorizedExecutionTicket, ExecutionAuthorizer
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import ExecutionRequest, ScopeToken, TargetSpec


def _req() -> ExecutionRequest:
    return ExecutionRequest(
        request_id="req_i30",
        tenant_id="t",
        target=TargetSpec(host="example.com"),
        stage="probe",
        scope_token=ScopeToken(scope_hash="scope-v1", allowed_domains=("example.com",)),
    )


def test_i30_ticket_binds_scope_reservation_revision_command() -> None:
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10), label="i30")
    auth = ExecutionAuthorizer(budget_enforcer=enforcer)
    ticket = auth.authorize(_req())
    assert_authorization_causality(ticket)
    assert ticket.scope_token_hash
    assert ticket.budget_reservation_id.startswith("hunt_")
    assert ticket.authority_revision
    assert ticket.command_id
    assert auth.verify_ticket(ticket) is True
    assert auth.consume_ticket(ticket) is True


def test_i30_ticket_without_bindings_is_rejected() -> None:
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10), label="i30b")
    auth = ExecutionAuthorizer(budget_enforcer=enforcer)
    good = auth.authorize(_req())
    bare = AuthorizedExecutionTicket(
        ticket_id=good.ticket_id,
        request_id=good.request_id,
        tenant_id=good.tenant_id,
        authorized_at=good.authorized_at,
        expires_at=good.expires_at,
        nonce=good.nonce,
        signature=good.signature,
        request=good.request,
    )
    with pytest.raises(AuthorizationCausalityError):
        assert_authorization_causality(bare)
    assert auth.consume_ticket(bare) is False


def test_i31_finding_requires_committed_wal() -> None:
    with pytest.raises(SettlementCausalityError):
        assert_settlement_causality(SettlementResult(execution_id="x", status="COMMITTED"))
    with pytest.raises(SettlementCausalityError):
        assert_settlement_causality(
            SettlementResult(execution_id="x", status="REJECTED", wal_id="wal_1")
        )
    assert_settlement_causality(
        SettlementResult(execution_id="x", status="COMMITTED", wal_id="wal_1")
    )


def test_i31_i32_outbox_then_bus_and_bus_failure_does_not_raise(tmp_path) -> None:
    reset_delivery_ledger()
    outbox = DurableOutboxLedger("P-0000", outbox_dir=tmp_path)
    seen: list[dict] = []

    def emit(event_type, *, source, data, trace_id=None):
        seen.append(data)
        raise RuntimeError("bus down")

    n = dispatch_committed_findings(
        settle_res=SettlementResult(
            execution_id="exec-1",
            status="COMMITTED",
            wal_id="wal_abc",
            committed_findings=({"title": "ok"},),
        ),
        stage_name="subdomains",
        findings=({"title": "ok"}, "skip"),
        emit=emit,
        event_type=SimpleNamespace(value="finding_created"),
        outbox=outbox,
    )
    assert n == 1
    assert seen[0]["wal_id"] == "wal_abc"
    assert seen[0].get("receipt_hmac")
    assert seen[0].get("settlement_status") == "COMMITTED"
    assert seen[0]["causation_id"] == "wal_abc"
    events = outbox.read_all_events()
    assert len(events) == 1
    assert events[0].event_type == "FINDING_CREATED"
    assert events[0].causation_id == "wal_abc"


def test_i30_consume_requires_recorded_reservation() -> None:
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10), label="i30c")
    auth = ExecutionAuthorizer(budget_enforcer=enforcer)
    ticket = auth.authorize(_req())
    enforcer._issued_identities.clear()
    assert auth.consume_ticket(ticket) is False


def test_i30_authorize_fails_closed_without_identity_api() -> None:
    from src.decision.authorization import ScopeAuthorizationError

    class _LegacyEnforcer:
        def reserve_requests(self, count: int = 1) -> bool:
            return True

    auth = ExecutionAuthorizer(budget_enforcer=_LegacyEnforcer())
    with pytest.raises(ScopeAuthorizationError, match="I30"):
        auth.authorize(_req())


def test_i31_event_bus_refuses_unauthoritative_finding() -> None:
    from src.core.events.event_bus import EventBus, EventType

    bus = EventBus()
    seen: list[object] = []
    bus.subscribe(EventType.FINDING_CREATED, seen.append)
    bus.emit(EventType.FINDING_CREATED, source="ghost", data={"title": "nope"})
    assert seen == []
    assert bus.dropped_status()["dropped_unauthoritative"] == 1
    bus.emit(
        EventType.FINDING_CREATED,
        source="ghost",
        data={"title": "self-attested", "wal_id": "wal_1", "authoritative": True},
    )
    assert seen == []
    from src.core.frontier.settlement_receipt import stamp_finding_receipt

    receipt = stamp_finding_receipt(wal_id="wal_1", settlement_id="stl_1", command_id="cmd_1")
    bus.emit(
        EventType.FINDING_CREATED,
        source="settlement.subdomains",
        data={"title": "ok", **receipt},
    )
    assert len(seen) == 1


def test_i31_dispatch_refuses_uncommitted() -> None:
    with pytest.raises(SettlementCausalityError):
        dispatch_committed_findings(
            settle_res=SettlementResult(execution_id="x", status="COMMITTED"),
            stage_name="s",
            findings=({"title": "ghost"},),
            emit=lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not emit")),
            event_type=None,
            outbox=None,
        )

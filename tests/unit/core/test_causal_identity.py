"""I33 complete causal identity chain: replay, retry, dedup, delivery."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.frontier.causal_identity import (
    CAUSAL_CHAIN,
    CausalIdentityError,
    assert_causal_identity_chain,
    derive_attempt_id,
    derive_delivery_id,
    derive_event_id_from_wal,
    derive_settlement_id,
    mint_causal_identity,
)
from src.core.frontier.event_delivery import (
    DeliveryLedger,
    dispatch_committed_findings,
    reset_delivery_ledger,
)
from src.core.frontier.state_authority import (
    SettlementCoordinator,
    SettlementResult,
    StateAuthority,
)
from src.core.models.stage_result import PipelineContext, StageResult


def test_i33_mint_is_deterministic_and_parent_linked() -> None:
    a = mint_causal_identity(execution_id="run:subdomains", command_id="cmd_auth", attempt_n=2)
    b = mint_causal_identity(execution_id="run:subdomains", command_id="cmd_auth", attempt_n=2)
    assert a == b
    assert a.command_id == "cmd_auth"
    assert a.execution_id == "run:subdomains"
    assert a.attempt_id == derive_attempt_id("run:subdomains", 2)
    assert a.settlement_id == derive_settlement_id(a.attempt_id)
    assert a.attempt_id != derive_attempt_id("run:subdomains", 1)
    assert_causal_identity_chain(a, up_to="settlement_id")
    assert CAUSAL_CHAIN == (
        "command_id",
        "execution_id",
        "attempt_id",
        "settlement_id",
        "wal_id",
        "event_id",
        "delivery_id",
    )


def test_i33_child_without_parent_is_rejected() -> None:
    ident = mint_causal_identity(execution_id="e1", command_id="c1")
    broken = ident.with_event("evt_orphan")
    with pytest.raises(CausalIdentityError, match="I33"):
        assert_causal_identity_chain(broken, up_to="event_id")
    with pytest.raises(CausalIdentityError, match="execution_id"):
        mint_causal_identity(execution_id="")


def test_i33_settle_stamps_full_chain_and_is_replay_stable() -> None:
    auth = StateAuthority()
    coord = SettlementCoordinator(state_authority=auth)
    ctx = PipelineContext(result=StageResult(), run_id="run-i33")
    output = StageOutput(
        stage_name="subdomains",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.1,
        retry_count=0,
        state_delta={"reportable_findings": [{"title": "ok"}]},
    )
    first = coord.settle_stage_output(ctx, "subdomains", output)
    assert first.status == "COMMITTED"
    assert first.command_id
    assert first.execution_id == "run-i33:subdomains"
    assert first.attempt_id == derive_attempt_id(first.execution_id, 1)
    assert first.settlement_id == derive_settlement_id(first.attempt_id)
    assert first.wal_id
    chain = first.causal_identity()
    assert chain is not None
    assert_causal_identity_chain(chain.with_wal(str(first.wal_id)), up_to="wal_id")

    second = coord.settle_stage_output(ctx, "subdomains", output)
    assert second.status == "DEDUPLICATED"
    assert second.attempt_id == first.attempt_id
    assert second.settlement_id == first.settlement_id


def test_i33_retry_gets_new_attempt_same_execution() -> None:
    auth = StateAuthority()
    coord = SettlementCoordinator(state_authority=auth)
    ctx = PipelineContext(result=StageResult(), run_id="run-retry")
    failed = StageOutput(
        stage_name="nuclei",
        outcome=StageOutcome.FAILED,
        duration_seconds=0.1,
        retry_count=0,
        error="timeout",
        state_delta={},
    )
    first = coord.settle_stage_output(ctx, "nuclei", failed)
    assert first.status == "REJECTED"
    assert first.attempt_id == derive_attempt_id("run-retry:nuclei", 1)

    recovered = StageOutput(
        stage_name="nuclei",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=0.2,
        retry_count=1,
        state_delta={"reportable_findings": [{"title": "recovered"}]},
    )
    second = coord.settle_stage_output(ctx, "nuclei", recovered)
    assert second.status == "COMMITTED"
    assert second.execution_id == first.execution_id
    assert second.attempt_id == derive_attempt_id("run-retry:nuclei", 2)
    assert second.attempt_id != first.attempt_id
    assert second.settlement_id != first.settlement_id
    assert second.wal_id


def test_i33_dispatch_binds_event_and_delivery_and_is_idempotent() -> None:
    reset_delivery_ledger()
    ledger = DeliveryLedger()
    seen: list[dict] = []

    def emit(event_type, *, source, data, trace_id=None):
        seen.append(data)

    settle = SettlementResult(
        execution_id="exec-i33",
        status="COMMITTED",
        wal_id="wal_i33",
        command_id="cmd_i33",
        attempt_id=derive_attempt_id("exec-i33", 1),
        settlement_id=derive_settlement_id(derive_attempt_id("exec-i33", 1)),
        committed_findings=({"title": "ok"},),
    )
    n1 = dispatch_committed_findings(
        settle_res=settle,
        stage_name="subdomains",
        findings=({"title": "ok"},),
        emit=emit,
        event_type=SimpleNamespace(value="finding_created"),
        outbox=None,
        delivery_ledger=ledger,
    )
    n2 = dispatch_committed_findings(
        settle_res=settle,
        stage_name="subdomains",
        findings=({"title": "ok"},),
        emit=emit,
        event_type=SimpleNamespace(value="finding_created"),
        outbox=None,
        delivery_ledger=ledger,
    )
    assert n1 == 1
    assert n2 == 1
    assert len(seen) == 1
    payload = seen[0]
    expected_event = derive_event_id_from_wal("wal_i33", 0)
    expected_delivery = derive_delivery_id(expected_event, 1)
    assert payload["command_id"] == "cmd_i33"
    assert payload["execution_id"] == "exec-i33"
    assert payload["attempt_id"]
    assert payload["settlement_id"]
    assert payload["wal_id"] == "wal_i33"
    assert payload["event_id"] == expected_event
    assert payload["delivery_id"] == expected_delivery
    assert payload["authoritative"] is True
    assert payload["causation_id"] == "wal_i33"

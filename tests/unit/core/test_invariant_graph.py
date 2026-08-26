"""Invariant dependency / proof graph: I35 cannot skip I30/I31; I37 cannot resurrect I30."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.frontier.authority_transfer import (
    AuthorityFenceError,
    TransferPhase,
    activate_lease,
)
from src.core.frontier.causal_identity import mint_causal_identity
from src.core.frontier.global_coordination import PlacementAuthority
from src.core.frontier.invariant_graph import (
    INVARIANT_GRAPH,
    InvariantId,
    ProofGraphError,
    assert_graph_sound,
    assert_requires,
    assert_transfer_does_not_resurrect,
    dependents_of,
    node_for,
    proof_catalog,
    transitive_prerequisites,
    verify_recovery_prerequisites,
)
from src.core.frontier.recovery_protocol import (
    CrashWindow,
    ObservedDurableState,
    RecoveryPhase,
    RecoveryPlane,
    run_recovery_protocol,
)
from src.core.frontier.state_authority import SettlementResult


def _ticket(
    *,
    scope: str = "scope-v1",
    reservation: str = "hunt_1",
    revision: str = "arev_1",
    command_id: str = "cmd_1",
    token: object | None = SimpleNamespace(),
) -> SimpleNamespace:
    return SimpleNamespace(
        scope_token_hash=scope,
        budget_reservation_id=reservation,
        authority_revision=revision,
        command_id=command_id,
        request=SimpleNamespace(scope_token=token),
    )


def test_proof_graph_is_sound_dag() -> None:
    assert_graph_sound()
    assert len(proof_catalog()) == len(InvariantId)
    assert set(INVARIANT_GRAPH) == set(InvariantId)
    for inv in InvariantId:
        node = node_for(inv)
        assert node.protects
        assert node.transitions
        assert node.crash_windows
        assert node.concurrency_windows
        assert node.recovery_rule
        assert node.tests
        assert node.module


def test_proof_graph_matches_declared_dependencies() -> None:
    assert_requires(InvariantId.I30, InvariantId.I22)
    assert_requires(InvariantId.I33, InvariantId.I30)
    assert_requires(InvariantId.I28, InvariantId.I30)
    assert_requires(InvariantId.I31, InvariantId.I33)
    assert_requires(InvariantId.I31, InvariantId.I28)
    assert_requires(InvariantId.I32, InvariantId.I31)
    assert_requires(InvariantId.I35, InvariantId.I32)
    assert_requires(InvariantId.I35, InvariantId.I30)
    assert_requires(InvariantId.I35, InvariantId.I31)
    assert_requires(InvariantId.I36, InvariantId.I35)
    assert_requires(InvariantId.I37, InvariantId.I36)
    assert_requires(InvariantId.I37, InvariantId.I30)
    i35 = transitive_prerequisites(InvariantId.I35)
    assert InvariantId.I22 in i35
    assert InvariantId.I28 in i35
    assert InvariantId.I33 in i35
    assert InvariantId.I37 in dependents_of(InvariantId.I30)
    assert InvariantId.I35 in dependents_of(InvariantId.I32)


def test_i35_ready_when_recovered_sets_are_empty() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            wal_present=True,
            snapshot_present=False,
        )
    )
    assert verdict.phase is RecoveryPhase.READY
    assert CrashWindow.PREREQUISITE_INVARIANT_FAILED not in verdict.windows


def test_i35_fail_closed_on_i30_invalid_recovered_ticket() -> None:
    bare = _ticket(scope="", reservation="", revision="", command_id="")
    bare.request = SimpleNamespace(scope_token=None)
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            wal_present=True,
            snapshot_present=False,
            recovered_tickets=(bare,),
        )
    )
    assert verdict.phase is RecoveryPhase.FAIL_CLOSED
    assert CrashWindow.PREREQUISITE_INVARIANT_FAILED in verdict.windows
    assert any("I30" in note for note in verdict.notes)


def test_i35_fail_closed_on_i31_committed_without_wal() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            wal_present=True,
            snapshot_present=False,
            recovered_settlements=(SettlementResult(execution_id="x", status="COMMITTED"),),
        )
    )
    assert verdict.phase is RecoveryPhase.FAIL_CLOSED
    assert CrashWindow.PREREQUISITE_INVARIANT_FAILED in verdict.windows
    assert any("I31" in note for note in verdict.notes)


def test_i35_ready_when_recovered_ticket_and_settlement_hold() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            wal_present=True,
            snapshot_present=False,
            recovered_tickets=(_ticket(),),
            recovered_settlements=(
                SettlementResult(execution_id="x", status="COMMITTED", wal_id="wal_1"),
            ),
            recovered_identities=(mint_causal_identity(execution_id="exec-1"),),
        )
    )
    assert verdict.phase is RecoveryPhase.READY


def test_i35_fail_closed_when_bus_emitted_without_outbox() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            wal_present=True,
            snapshot_present=False,
            bus_emitted_without_outbox=True,
        )
    )
    assert verdict.phase is RecoveryPhase.FAIL_CLOSED
    assert CrashWindow.PREREQUISITE_INVARIANT_FAILED in verdict.windows
    assert any("I32" in note for note in verdict.notes)


def test_i35_fail_closed_on_broken_causal_identity() -> None:
    broken = SimpleNamespace(
        command_id="",
        execution_id="exec-1",
        attempt_id="att_1",
        settlement_id="stl_1",
        wal_id="",
        event_id="",
        delivery_id="",
    )
    with pytest.raises(ProofGraphError, match="I33"):
        verify_recovery_prerequisites(SimpleNamespace(recovered_identities=(broken,)))


def test_i37_activate_refuses_i30_invalid_ticket() -> None:
    placement = PlacementAuthority(home_region="us-east")
    epoch = placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="eu-west")
    bare = _ticket(scope="", reservation="", revision="", command_id="")
    bare.request = SimpleNamespace(scope_token=None)
    with pytest.raises(AuthorityFenceError, match="I30"):
        placement.activate_ownership("agg", "P-0000", epoch, recovered_tickets=(bare,))
    assert placement.is_fenced("P-0000") is True
    assert placement.lease_for("P-0000").phase is TransferPhase.FENCED


def test_i37_activate_allows_stale_i30_valid_tickets_then_they_die() -> None:
    placement = PlacementAuthority(home_region="us-east")
    old_rev = placement.current_revision("P-0000")
    epoch = placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="eu-west")
    stale = _ticket(revision=old_rev)
    assert placement.activate_ownership("agg", "P-0000", epoch, recovered_tickets=(stale,)) is True
    assert placement.is_fenced("P-0000") is False
    live = placement.current_revision("P-0000")
    assert live != old_rev
    with pytest.raises(ProofGraphError, match="I37"):
        verify_recovery_prerequisites(
            SimpleNamespace(recovered_tickets=(stale,), live_authority_revision=live)
        )


def test_i37_cannot_mint_ticket_bound_to_post_activate_revision() -> None:
    placement = PlacementAuthority(home_region="us-east")
    epoch = placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="eu-west")
    fenced = placement.lease_for("P-0000")
    predicted = activate_lease(fenced, placement_version=placement.placement_version + 1)
    forged = _ticket(revision=predicted.authority_revision)
    with pytest.raises(AuthorityFenceError, match="cannot mint I30"):
        placement.activate_ownership("agg", "P-0000", epoch, recovered_tickets=(forged,))
    assert placement.is_fenced("P-0000") is True


def test_collect_recovered_artifacts_from_payload_and_wal() -> None:
    from src.core.frontier.invariant_graph import collect_recovered_proof_artifacts

    class _Wal:
        entries = (
            {
                "_is_settlement_intent": True,
                "execution_id": "exec-1",
                "command_id": "cmd_1",
                "attempt_id": "att_1",
                "settlement_id": "stl_1",
                "state_delta": {"findings": [{"title": "x"}]},
                "_wal_id": "wal_1",
            },
        )

    artifacts = collect_recovered_proof_artifacts(
        payload={
            "tickets": [
                {
                    "scope_token_hash": "s",
                    "budget_reservation_id": "hunt_1",
                    "authority_revision": "arev_1",
                    "command_id": "cmd_1",
                    "request": {"scope_token": {"scope_hash": "s"}},
                }
            ]
        },
        wal=_Wal(),
    )
    assert len(artifacts.tickets) == 1
    assert artifacts.tickets[0].command_id == "cmd_1"
    assert artifacts.settlements[0].status == "COMMITTED"
    assert artifacts.settlements[0].wal_id == "wal_1"
    verify_recovery_prerequisites(
        SimpleNamespace(
            recovered_tickets=artifacts.tickets,
            recovered_settlements=artifacts.settlements,
            recovered_identities=artifacts.identities,
        )
    )


def test_collect_wal_finding_without_wal_id_fails_i31() -> None:
    from src.core.frontier.invariant_graph import collect_recovered_proof_artifacts

    class _Wal:
        entries = (
            {
                "_is_settlement_intent": True,
                "execution_id": "exec-ghost",
                "state_delta": {"findings": [{"title": "ghost"}]},
            },
        )

    artifacts = collect_recovered_proof_artifacts(wal=_Wal())
    with pytest.raises(ProofGraphError, match="I31"):
        verify_recovery_prerequisites(SimpleNamespace(recovered_settlements=artifacts.settlements))


def test_hmac_receipt_does_not_use_published_fallback() -> None:
    from src.core.frontier import receipt_crypto

    source = Path(receipt_crypto.__file__).read_text(encoding="utf-8")
    assert "singularity-zero-dev-receipt-key" not in source
    sig = receipt_crypto.sign_receipt({"command_id": "c"})
    assert receipt_crypto.verify_receipt_signature({"command_id": "c"}, sig) is True


def test_i37_fenced_partition_refuses_settle() -> None:
    from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
    from src.core.frontier.global_coordination import PlacementAuthority
    from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
    from src.core.models.stage_result import PipelineContext, StageResult

    placement = PlacementAuthority(home_region="us-east")
    placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="eu-west")
    ctx = PipelineContext(result=StageResult(), run_id="r1")
    ctx.placement = placement  # type: ignore[attr-defined]
    coord = SettlementCoordinator(StateAuthority())
    res = coord.settle_stage_output(
        ctx,
        "urls",
        StageOutput(stage_name="urls", outcome=StageOutcome.COMPLETED),
    )
    assert res.status == "REJECTED"
    assert "I37" in (res.error or "")


def test_assert_transfer_does_not_resurrect_i30_invalid() -> None:
    bare = _ticket(scope="", reservation="r", revision="arev", command_id="c")
    bare.request = SimpleNamespace(scope_token=None)
    with pytest.raises(ProofGraphError, match="I30-invalid"):
        assert_transfer_does_not_resurrect((bare,), live_revision="arev_new")

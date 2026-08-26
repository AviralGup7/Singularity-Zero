"""I37: home transfer is a fence. Nobody writes in the gap."""

from __future__ import annotations

import pytest

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.frontier.authority_transfer import (
    I37_AUTHORITY_TRANSFER,
    AuthorityFenceError,
    TransferPhase,
    assert_mutation_allowed,
    assert_ticket_revision_live,
)
from src.core.frontier.global_coordination import PlacementAuthority
from src.core.frontier.replicated_log import ReplicatedPartitionLog


def _cmd(cid: str = "cmd_i37") -> CommandEnvelope:
    return CommandEnvelope(
        command_id=cid,
        command_type="AllocateSubLeaseCommand",
        aggregate_id="sl",
        payload={"sublease_id": "sl", "units_allocated": 1, "run_id": "R"},
        correlation_id="c",
        causation_id="x",
    )


def test_i37_fence_has_no_writer_then_only_new_home() -> None:
    placement = PlacementAuthority(home_region="us-east")
    old = ReplicatedPartitionLog(
        partition_id="P-0001",
        is_leader=True,
        local_region="us-east",
        leader_region="us-east",
    )
    old.bind_placement(placement)
    old.install_authority(placement.lease_for("P-0001"))

    old.propose_and_commit(_cmd("cmd_before"))

    epoch = placement.initiate_transfer(
        "agg-home",
        "P-0001",
        "P-0001",
        to_region="eu-west",
    )
    assert placement.is_fenced("P-0001") is True
    assert placement.region_for_partition("P-0001") == "us-east"
    assert placement.lease_for("P-0001").phase is TransferPhase.FENCED

    with pytest.raises(AuthorityFenceError, match=I37_AUTHORITY_TRANSFER):
        old.propose_and_commit(_cmd("cmd_during_fence"))

    new = ReplicatedPartitionLog(
        partition_id="P-0001",
        is_leader=True,
        local_region="eu-west",
        leader_region="eu-west",
    )
    new.bind_placement(placement)
    with pytest.raises(AuthorityFenceError, match="FENCED"):
        new.propose_and_commit(_cmd("cmd_new_too_early"))

    rec = placement._transfers["agg-home"]
    assert placement.activate_ownership("agg-home", "P-0001", epoch, rec.fence_token) is True
    assert placement.is_fenced("P-0001") is False
    assert placement.region_for_partition("P-0001") == "eu-west"

    new.install_authority(placement.lease_for("P-0001"))
    new.propose_and_commit(_cmd("cmd_after"))

    with pytest.raises(AuthorityFenceError, match="stale"):
        old.propose_and_commit(_cmd("cmd_old_after"))


def test_i37_stale_epoch_and_token_rejected() -> None:
    placement = PlacementAuthority(home_region="local")
    lease = placement.lease_for("P-0000")
    assert_mutation_allowed(
        lease,
        observed_region="local",
        observed_epoch=lease.authority_epoch,
        observed_token=lease.fence_token,
        observed_term=lease.leader_term,
    )
    with pytest.raises(AuthorityFenceError, match="stale authority epoch"):
        assert_mutation_allowed(
            lease,
            observed_region="local",
            observed_epoch=lease.authority_epoch - 1,
            observed_token=lease.fence_token,
        )
    placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="local")
    fenced = placement.lease_for("P-0000")
    with pytest.raises(AuthorityFenceError, match="FENCED"):
        assert_mutation_allowed(
            fenced,
            observed_region="local",
            observed_epoch=fenced.authority_epoch,
            observed_token=fenced.fence_token,
        )


def test_i37_ticket_dies_after_activate() -> None:
    from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer

    placement = PlacementAuthority(home_region="us-east")
    enforcer = HuntBudgetEnforcer(
        HuntBudget(max_requests=50, label="t"),
        partition_id="P-0000",
        run_id="r",
        placement=placement,
    )
    ident = enforcer.reserve_with_identity(1)
    assert ident is not None
    live_before = ident["authority_revision"]
    assert_ticket_revision_live(live_before, enforcer.live_authority_revision())

    epoch = placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="eu-west")
    placement.activate_ownership("agg", "P-0000", epoch)
    with pytest.raises(AuthorityFenceError, match="not live"):
        assert_ticket_revision_live(live_before, enforcer.live_authority_revision())


def test_i37_wrong_token_cannot_activate() -> None:
    placement = PlacementAuthority(home_region="us-east")
    epoch = placement.initiate_transfer("agg", "P-0000", "P-0000", to_region="eu-west")
    assert placement.activate_ownership("agg", "P-0000", epoch, "fnc_forged") is False
    assert placement.is_fenced("P-0000") is True
    assert placement.activate_ownership("agg", "P-0000", epoch) is True

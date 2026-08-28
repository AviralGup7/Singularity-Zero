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

    with pytest.raises(AuthorityFenceError, match=I37_AUTHORITY_TRANSFER):
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


def test_i37_transfer_abort_resumes_original_home() -> None:
    placement = PlacementAuthority(home_region="us-east")
    log = ReplicatedPartitionLog(
        partition_id="P-0002",
        is_leader=True,
        local_region="us-east",
        leader_region="us-east",
    )
    log.bind_placement(placement)
    log.install_authority(placement.lease_for("P-0002"))
    log.propose_and_commit(_cmd("cmd_1"))

    epoch = placement.initiate_transfer("agg-abort", "P-0002", "P-0002", to_region="eu-west")
    assert placement.is_fenced("P-0002") is True

    # Abort transfer (e.g. on timeout or network partition)
    assert placement.abort_transfer("agg-abort", epoch) is True
    assert placement.is_fenced("P-0002") is False
    assert placement.region_for_partition("P-0002") == "us-east"

    # Original home resumes writes after installing new revision
    log.install_authority(placement.lease_for("P-0002"))
    log.propose_and_commit(_cmd("cmd_resumed"))

    # Foreign writer remains rejected
    foreign = ReplicatedPartitionLog(
        partition_id="P-0002",
        is_leader=True,
        local_region="eu-west",
        leader_region="eu-west",
    )
    foreign.bind_placement(placement)
    with pytest.raises(AuthorityFenceError, match=I37_AUTHORITY_TRANSFER):
        foreign.propose_and_commit(_cmd("cmd_foreign"))


def test_i37_wal_boundary_rejects_stale_epoch_appends() -> None:
    """WAL append boundary directly enforces epoch >= active_epoch."""
    log = ReplicatedPartitionLog(
        partition_id="P-0003",
        is_leader=True,
        local_region="us-east",
    )
    # Simulate active epoch 3 on the partition WAL
    log.wal.cas_fence_epoch(expected_epoch=1, new_epoch=3, new_token="fnc_3")
    assert log.wal.active_epoch == 3

    entry = _cmd("cmd_stale_wal")
    # An append carrying a stale epoch < 3 must be refused at the physical WAL level
    from src.core.contracts.command_envelope import CommandResult, CommittedEntry
    stale_candidate = CommittedEntry(
        partition_id="P-0003",
        raft_term=1,
        raft_index=1,
        entry_hash="hash_dummy",
        previous_entry_hash="0" * 64,
        command=entry,
        transition_result=CommandResult(
            status="SUCCESS",
            aggregate_id="sl",
            resulting_aggregate_version=1,
            result_code="PENDING",
        ),
    )

    with pytest.raises(AuthorityFenceError, match="I37_WAL_BOUNDARY"):
        log.wal.append_entry(stale_candidate, committed=False, epoch=2)


def test_i37_chaos_kill_coordinator_mid_transfer() -> None:
    """Chaos test: Coordinator crashes mid-transfer after fence; zero dual-writer mutations succeed."""
    placement = PlacementAuthority(home_region="us-east")
    old_leader = ReplicatedPartitionLog(
        partition_id="P-0004",
        is_leader=True,
        local_region="us-east",
    )
    old_leader.bind_placement(placement)
    old_leader.install_authority(placement.lease_for("P-0004"))
    old_leader.propose_and_commit(_cmd("cmd_live_1"))

    # 1. Initiate transfer (Stage 1: Fenced)
    epoch = placement.initiate_transfer("agg-chaos", "P-0004", "P-0004", to_region="eu-west")
    assert placement.is_fenced("P-0004")

    # 2. CHAOS: Coordinator crashes / dies mid-transfer. Both nodes attempt to write.
    candidate_new_leader = ReplicatedPartitionLog(
        partition_id="P-0004",
        is_leader=True,
        local_region="eu-west",
        leader_region="eu-west",
    )
    candidate_new_leader.bind_placement(placement)

    # Neither old leader nor new candidate can commit mutations while fenced
    with pytest.raises(AuthorityFenceError, match="FENCED"):
        old_leader.propose_and_commit(_cmd("cmd_old_during_crash"))

    with pytest.raises(AuthorityFenceError, match="FENCED"):
        candidate_new_leader.propose_and_commit(_cmd("cmd_new_during_crash"))

    # 3. Coordinator recovers and aborts stale abandoned transfer
    placement.abort_transfer("agg-chaos", epoch)
    assert not placement.is_fenced("P-0004")

    # Old leader re-adopts fresh lease (epoch bumped) and resumes single-writer operations
    old_leader.install_authority(placement.lease_for("P-0004"))
    receipt, _ = old_leader.propose_and_commit(_cmd("cmd_recovered"))
    assert receipt.receipt_id is not None

    # Candidate in eu-west attempting to write without ownership is rejected
    with pytest.raises(AuthorityFenceError, match=I37_AUTHORITY_TRANSFER):
        candidate_new_leader.propose_and_commit(_cmd("cmd_rogue_writer"))

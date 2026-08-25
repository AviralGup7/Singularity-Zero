"""I36 multi-region consistency: one writer, not active-active authority."""

from __future__ import annotations

import pytest

from src.core.frontier.global_coordination import PlacementAuthority
from src.core.frontier.region_model import (
    I36_REGION_CONSISTENCY,
    REGION_CONTRACT,
    ObservedRegionState,
    RegionConsistencyError,
    RegionDecision,
    RegionQuestion,
    RegionRole,
    assert_budget_home,
    assert_lease_settle_colocated,
    assert_migration_allowed,
    assert_region_may_accept_command,
    classify_peer_entry,
    evaluate_region_policy,
    region_catalog,
    resolve_authority_revision,
)
from src.infrastructure.frontier.replication import WALReplicationRelay


def test_i36_contract_answers_every_region_question() -> None:
    assert set(REGION_CONTRACT) == set(RegionQuestion)
    assert len(region_catalog()) == len(RegionQuestion)
    assert (
        REGION_CONTRACT[RegionQuestion.REGION_IS_AUTHORITY_DOMAIN].decision is RegionDecision.REFUSE
    )
    assert REGION_CONTRACT[RegionQuestion.BOTH_REGIONS_WRITABLE].decision is RegionDecision.REFUSE
    assert REGION_CONTRACT[RegionQuestion.BUDGET_SPANS_REGIONS].decision is RegionDecision.REFUSE
    assert (
        REGION_CONTRACT[RegionQuestion.LEASE_ACQUIRE_A_SETTLE_B].decision is RegionDecision.REFUSE
    )
    assert REGION_CONTRACT[RegionQuestion.MIGRATE_AFTER_ATTEMPT].decision is RegionDecision.REFUSE
    assert "partition" in REGION_CONTRACT[RegionQuestion.WAL_ORDERING].answer.lower()


def test_i36_replica_and_foreign_region_cannot_accept_commands() -> None:
    assert_region_may_accept_command(
        local_region="us-east",
        leader_region="us-east",
        role=RegionRole.AUTHORITY_HOME,
        partition_id="P-0001",
    )
    with pytest.raises(RegionConsistencyError, match=I36_REGION_CONSISTENCY):
        assert_region_may_accept_command(
            local_region="eu-west",
            leader_region="us-east",
            role=RegionRole.AUTHORITY_HOME,
            partition_id="P-0001",
        )
    with pytest.raises(RegionConsistencyError, match="replica"):
        assert_region_may_accept_command(
            local_region="us-east",
            leader_region="us-east",
            role=RegionRole.REPLICA,
        )
    with pytest.raises(RegionConsistencyError, match="partitioned"):
        assert_region_may_accept_command(
            local_region="us-east",
            leader_region="us-east",
            role=RegionRole.PARTITIONED,
        )


def test_i36_budget_and_lease_do_not_span_regions() -> None:
    assert_budget_home(local_region="local", p0000_region="local")
    with pytest.raises(RegionConsistencyError, match="budget"):
        assert_budget_home(local_region="eu-west", p0000_region="us-east")
    assert_lease_settle_colocated(acquire_region="us-east", settle_region="us-east")
    with pytest.raises(RegionConsistencyError, match="cannot be settled"):
        assert_lease_settle_colocated(acquire_region="us-east", settle_region="eu-west")


def test_i36_migration_forbidden_while_attempt_in_flight() -> None:
    assert_migration_allowed(attempt_in_flight=False)
    assert_migration_allowed(attempt_in_flight=True, attempt_terminal=True)
    with pytest.raises(RegionConsistencyError, match="attempt starts"):
        assert_migration_allowed(attempt_in_flight=True, attempt_terminal=False)
    placement = PlacementAuthority(home_region="us-east")
    with pytest.raises(RegionConsistencyError, match=I36_REGION_CONSISTENCY):
        placement.initiate_transfer("agg-1", "P-0001", "P-0002", attempt_in_flight=True)
    epoch = placement.initiate_transfer(
        "agg-1",
        "P-0001",
        "P-0002",
        attempt_in_flight=True,
        attempt_terminal=True,
        to_region="eu-west",
    )
    assert epoch >= 2
    assert placement.region_for_partition("P-0002") == "eu-west"


def test_i36_heal_uses_placement_version_not_lww() -> None:
    assert (
        resolve_authority_revision(local_placement_version=3, remote_placement_version=7)
        == "remote"
    )
    assert (
        resolve_authority_revision(local_placement_version=9, remote_placement_version=4) == "local"
    )
    assert (
        resolve_authority_revision(
            local_placement_version=5,
            remote_placement_version=5,
            local_state_hash="aaa",
            remote_state_hash="aaa",
        )
        == "equal"
    )
    with pytest.raises(RegionConsistencyError, match="divergent"):
        resolve_authority_revision(
            local_placement_version=5,
            remote_placement_version=5,
            local_state_hash="aaa",
            remote_state_hash="bbb",
        )


def test_i36_peer_settlement_is_not_local_authority() -> None:
    assert classify_peer_entry({"urls": ["https://a.example"]}) is RegionDecision.JOURNAL_ONLY
    assert (
        classify_peer_entry({"_is_settlement_intent": True, "execution_id": "e"})
        is RegionDecision.REFUSE
    )
    assert classify_peer_entry({"state_delta": {"findings": []}}) is RegionDecision.REFUSE
    assert (
        classify_peer_entry({"command_type": "ReserveGlobalBudgetCommand"}) is RegionDecision.REFUSE
    )


class _WouldCommit:
    def __init__(self) -> None:
        self.committed = False

    def is_committed(self, _exec_id: str) -> bool:
        return False

    def append_settlement_intent(self, _intent: object) -> str:
        self.committed = True
        return "wal_should_not_exist"


def test_i36_relay_reconcile_does_not_commit_peer_settlement() -> None:
    relay = WALReplicationRelay(local_wal=None, peer_redis_urls=[], run_id="r1")
    authority = _WouldCommit()
    applied = relay.reconcile_with_peer("redis://peer:6379/0", state_authority=authority)
    assert applied == 0
    assert authority.committed is False


def test_i36_evaluate_partitioned_replica_fail_closed() -> None:
    verdict = evaluate_region_policy(
        ObservedRegionState(
            local_region="eu-west",
            leader_region="us-east",
            p0000_region="us-east",
            acquire_region="us-east",
            settle_region="eu-west",
            attempt_in_flight=True,
            network_partitioned=True,
            local_placement_version=2,
            remote_placement_version=2,
            local_state_hash="h1",
            remote_state_hash="h2",
        )
    )
    assert verdict.may_accept_commands is False
    assert verdict.may_reserve_budget is False
    assert verdict.may_settle_lease is False
    assert verdict.may_migrate is False
    assert verdict.heal_winner == "fail_closed"
    assert verdict.role is RegionRole.PARTITIONED

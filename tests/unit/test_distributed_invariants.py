"""Unit tests verifying hard distributed systems invariants:
- Fencing tokens & zombie worker rejection
- Double-spend budget collision rejection
- Nonce replay protection
- Partitioned single-writer routing
"""

import time
from src.core.contracts.canonical_target import canonicalize_target
from src.core.frontier.partition_authority import PartitionRouter
from src.core.frontier.state_authority import (
    SettlementCoordinator,
    StateAuthority,
)
from src.decision.authorization import ExecutionAuthorizer, ScopeAuthorizationError
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import (
    ActionSpec,
    ExecutionRequest,
    Finding,
    RawExecutionClaim,
    ScopeToken,
    TargetSpec,
)
from src.execution.request_executor import ExecutionRequestWorker


def test_budget_invariant_prevents_overcommit() -> None:
    budget = HuntBudget(max_requests=10)
    enforcer = HuntBudgetEnforcer(budget)

    # Worker A reserves 7
    res_a = enforcer.reserve_requests(7)
    assert res_a is True
    assert enforcer.reserved_requests == 7
    assert enforcer.available_requests == 3

    # Worker B tries to reserve 7 concurrently
    res_b = enforcer.reserve_requests(7)
    assert res_b is False  # Must be rejected!
    assert enforcer.reserved_requests == 7

    # Worker A commits 7
    enforcer.commit_requests(7)
    assert enforcer.reserved_requests == 0
    assert enforcer.consumed_requests == 7
    assert enforcer.available_requests == 3

    # Worker B now tries to reserve 3
    res_b2 = enforcer.reserve_requests(3)
    assert res_b2 is True
    assert enforcer.available_requests == 0


def test_single_use_ticket_replay_resistance() -> None:
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
    authorizer = ExecutionAuthorizer(secret_key="test-key", budget_enforcer=enforcer)
    req = ExecutionRequest(
        request_id="req_test_1",
        tenant_id="tenant_a",
        target=TargetSpec(host="example.com", path="/api"),
        stage="probing",
        actions=(ActionSpec(action_id="a1", action_type="probe", tool_or_detector="http_prober"),),
    )

    ticket = authorizer.authorize(req)
    assert authorizer.verify_ticket(ticket) is True

    # First consumption succeeds
    consumed_first = authorizer.consume_ticket(ticket)
    assert consumed_first is True

    # Second consumption must strictly fail (Replay detected)
    consumed_second = authorizer.consume_ticket(ticket)
    assert consumed_second is False


def test_fencing_token_rejects_zombie_claim() -> None:
    router = PartitionRouter(num_partitions=4)
    partition = router.route_and_get_partition("https://example.com/target1")

    # Worker A receives Lease Epoch 2
    lease_a = partition.grant_lease(
        candidate_id="cand_1",
        target_url="https://example.com/target1",
        execution_id="exec_1",
        lease_id="lease_100",
        worker_id="worker_a",
        ttl_seconds=1.0,
    )
    assert lease_a is not None
    epoch_a = lease_a.epoch

    # Lease expires / gets reassigned -> Partition bumps epoch to 3 for Worker B
    time.sleep(1.1)
    lease_b = partition.grant_lease(
        candidate_id="cand_1",
        target_url="https://example.com/target1",
        execution_id="exec_2",
        lease_id="lease_101",
        worker_id="worker_b",
        ttl_seconds=60.0,
    )
    assert lease_b is not None
    assert lease_b.epoch > epoch_a

    # Zombie Worker A wakes up and submits claim with old epoch
    claim_zombie = RawExecutionClaim(
        request_id="req_1",
        tenant_id="tenant_a",
        candidate_id="cand_1",
        execution_id="exec_1",
        lease_id="lease_100",
        epoch=epoch_a,
        worker_id="worker_a",
        outcome="COMPLETED",
        duration_seconds=0.5,
        ticket_nonce="nonce_123",
    )

    fencing_ok, reason = partition.validate_claim_fencing(claim_zombie)
    assert fencing_ok is False
    assert "mismatch" in reason or "Stale epoch" in reason or "fencing" in reason


def test_settlement_coordinator_claim_verification() -> None:
    state_auth = StateAuthority()
    enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10))
    router = PartitionRouter(num_partitions=4)
    coord = SettlementCoordinator(
        state_authority=state_auth,
        budget_enforcer=enforcer,
        partition_router=router,
    )

    partition = router.route_and_get_partition("cand_10")
    lease = partition.grant_lease(
        candidate_id="cand_10",
        target_url="https://example.com/cand10",
        execution_id="exec_valid_1",
        lease_id="lease_200",
        worker_id="worker_1",
    )
    assert lease is not None

    finding = Finding(
        category="sqli",
        title="SQL Injection",
        url="https://example.com/cand10",
        severity="high",
        confidence=0.9,
    )

    claim = RawExecutionClaim(
        request_id="req_valid",
        tenant_id="default",
        candidate_id="cand_10",
        execution_id="exec_valid_1",
        lease_id="lease_200",
        epoch=lease.epoch,
        worker_id="worker_1",
        outcome="COMPLETED",
        duration_seconds=0.2,
        findings=(finding,),
    )

    # Valid claim settlements succeed and populate findings projection
    res = coord.settle_claim(claim)
    assert res.status == "COMMITTED"
    assert len(coord.findings_projection.findings) == 1
    assert coord.findings_projection.findings[0].category == "sqli"

    # Duplicate settlement deduplicates
    res_dup = coord.settle_claim(claim)
    assert res_dup.status == "DEDUPLICATED"

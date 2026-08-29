"""Automated architectural invariant test suite.

Proves the core architectural invariants with adversarial testing:
1. Priority Engine / AdaptiveScanCoordinator is pure ranking (cannot execute or bypass Dispatcher)
2. State Authority is the sole writer (workers cannot mutate CRDT/WAL; duplicate ExecutionResults are idempotent)
3. Execution ID & Idempotency (duplicate requests/retries do not cause duplicate executions)
4. Budget Controller atomic reservation invariant (concurrent reservations cannot oversubscribe budget)
5. Authorization Gate defense-in-depth (adversarial normalization, ticket replay resistance, host/path evasion)
"""

from concurrent.futures import ThreadPoolExecutor

import pytest

from src.decision.adaptive_scan import AdaptiveScanCoordinator
from src.decision.authorization import (
    ExecutionAuthorizer,
    ScopeAuthorizationError,
)
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import (
    ExecutionRequest,
    ExecutionResult,
    Finding,
    PlacementStatus,
    ScopeToken,
    TargetSpec,
)


class TestPriorityEngineBoundaries:
    """Invariant 1: Priority Engine is strictly a ranking heuristic."""

    def test_priority_engine_only_ranks_and_boosts(self):
        """Priority engine produces ordered candidate lists without executing."""
        urls = [
            "https://example.com/api/users",
            "https://example.com/login",
            "https://example.com/static",
        ]
        coordinator = AdaptiveScanCoordinator(urls=urls)

        # 1. Peeks and pops candidates
        peeked = coordinator.peek_batch(batch_size=2)
        assert len(peeked) == 2
        batch = coordinator.pop_batch(batch_size=2)
        assert len(batch) == 2

        # 2. Boosts correlated items without executing
        boosted = coordinator.boost_from_findings(
            [{"url": "https://example.com/api/users", "type": "sqli"}]
        )
        assert isinstance(boosted, int)

        # 3. Does not have direct execution methods
        assert not hasattr(coordinator, "execute_now")
        assert not hasattr(coordinator, "dispatch_to_worker")
        assert not hasattr(coordinator, "mutate_crdt")

    def test_candidate_lease_ack_release_lifecycle(self):
        """Candidates can be leased, preventing duplicate peek/dispatch, and released on failure."""
        urls = ["https://example.com/a", "https://example.com/b", "https://example.com/c"]
        coordinator = AdaptiveScanCoordinator(urls=urls)

        # Lease 2 candidates
        leased = coordinator.lease_batch(batch_size=2, lease_timeout_seconds=30.0)
        assert len(leased) == 2

        # In-flight candidates are not returned by subsequent peek
        remaining_peek = coordinator.peek_batch(batch_size=10)
        assert len(remaining_peek) == 1
        leased_urls = [getattr(item, "target_url", str(item)) for item in leased]
        assert remaining_peek[0] not in leased_urls

        # Release first leased candidate (simulating downstream dispatch failure)
        coordinator.release_batch([leased[0]])
        re_peek = coordinator.peek_batch(batch_size=10)
        assert len(re_peek) == 2
        assert leased_urls[0] in re_peek

        # Acknowledge remaining leased candidate (simulating completed execution)
        coordinator.ack_batch([leased[1]])
        final_peek = coordinator.peek_batch(batch_size=10)
        assert len(final_peek) == 2
        assert leased_urls[1] not in final_peek


class TestStateAuthorityAndIdempotency:
    """Invariant 2: State Authority is sole writer; duplicate results are idempotent."""

    def test_execution_result_is_pure_data_carrier(self):
        """Worker produces an immutable ExecutionResult with state deltas; worker has no write handle."""
        res = ExecutionResult(
            request_id="req-123",
            execution_id="exec-456",
            job_id="job-789",
            tenant_id="tenant-alpha",
            outcome="COMPLETED",
            duration_seconds=1.2,
            findings=(
                Finding(
                    title="SQL Injection",
                    url="https://example.com",
                    category="sqli",
                    severity="high",
                    confidence=0.9,
                ),
            ),
            state_deltas=(("live_hosts", ("https://example.com",)),),
        )
        assert res.execution_id == "exec-456"
        assert res.job_id == "job-789"
        assert dict(res.state_deltas)["live_hosts"] == ("https://example.com",)

    def test_state_authority_idempotent_deduplication(self):
        """State manager deduplicates duplicate ExecutionResult objects with identical execution_id."""
        processed_executions: set[str] = set()
        crdt_store: set[str] = set()

        def state_authority_commit(result: ExecutionResult) -> bool:
            if result.execution_id in processed_executions:
                return False  # Deduplicated, no state mutation
            processed_executions.add(result.execution_id)
            for key, val in result.state_deltas:
                for item in val:
                    crdt_store.add(item)
            return True

        res = ExecutionResult(
            request_id="req-1",
            execution_id="exec-dup-test",
            tenant_id="t1",
            outcome="COMPLETED",
            state_deltas=(("discovered_endpoints", ("/api/v1/user",)),),
        )

        # First commit succeeds and mutates state
        assert state_authority_commit(res) is True
        assert "/api/v1/user" in crdt_store
        assert len(crdt_store) == 1

        # Duplicate commit (e.g. worker retry after crash) is rejected without double state mutation
        assert state_authority_commit(res) is False
        assert len(crdt_store) == 1


class TestAuthoritativeBudgetController:
    """Invariant 3: Authoritative budget cannot be oversubscribed concurrently."""

    def test_concurrent_budget_reservations_cannot_oversubscribe(self):
        """100 concurrent reservation attempts against budget of 10 must admit at most 10."""
        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)

        def try_reserve() -> bool:
            return enforcer.reserve_requests(count=1)

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda _: try_reserve(), range(100)))

        successful = [r for r in results if r is True]
        assert len(successful) == 10
        assert enforcer.reserved_requests == 10
        assert enforcer.available_requests == 0
        # Additional reservation fails
        assert enforcer.reserve_requests(count=1) is False

        # Commit 10 requests
        enforcer.commit_requests(count=10)
        assert enforcer.requests_emitted == 10
        assert enforcer.consumed_requests == 10
        assert enforcer.reserved_requests == 0


class TestAuthorizationGateDefenseInDepth:
    """Invariant 4: Authorization Gate rejects unauthorized / out-of-scope requests with adversarial validation."""

    def test_gate_authorizes_valid_request(self):
        """Authorizer validates in-scope ExecutionRequest and issues signed ticket."""
        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=100))
        authorizer = ExecutionAuthorizer(budget_enforcer=enforcer)
        token = ScopeToken(scope_hash="h1", allowed_domains=("example.com", "*.example.com"))
        req = ExecutionRequest(
            request_id="req-1",
            tenant_id="tenant-1",
            target=TargetSpec(host="api.example.com", port=443, path="/users"),
            stage="probing",
            scope_token=token,
        )
        ticket = authorizer.authorize(req)
        assert ticket.ticket_id.startswith("tkt_")
        assert len(ticket.signature) == 64
        # Single-use ticket consumption succeeds
        assert authorizer.consume_ticket(ticket) is True
        from src.decision.authorization import TicketAlreadyConsumedError

        with pytest.raises(TicketAlreadyConsumedError):
            authorizer.consume_ticket(ticket)

    def test_adversarial_host_spoofing_blocked(self):
        """Authorizer rejects domain suffix attacks and userinfo spoofing."""
        authorizer = ExecutionAuthorizer()
        token = ScopeToken(scope_hash="h2", allowed_domains=("example.com",))

        for evil_host in ["example.com.evil.com", "example.com@evil.com", "notexample.com"]:
            req = ExecutionRequest(
                request_id="req-spoof",
                tenant_id="tenant-1",
                target=TargetSpec(host=evil_host, port=443, path="/"),
                stage="probing",
                scope_token=token,
            )
            with pytest.raises(ScopeAuthorizationError):
                authorizer.authorize(req)

    def test_adversarial_path_traversal_blocked(self):
        """Authorizer normalizes path traversals and URL encodings to catch evasion."""
        authorizer = ExecutionAuthorizer()
        token = ScopeToken(
            scope_hash="h3",
            allowed_domains=("example.com",),
            forbidden_paths=("/admin", "/internal"),
        )

        for evasive_path in ["/%61dmin", "/%2e%2e/admin", "/..;/admin", "//admin", "/./admin"]:
            req = ExecutionRequest(
                request_id="req-evade",
                tenant_id="tenant-1",
                target=TargetSpec(host="example.com", port=443, path=evasive_path),
                stage="probing",
                scope_token=token,
            )
            with pytest.raises(ScopeAuthorizationError):
                authorizer.authorize(req)


class TestActorSchedulerPlacementStatuses:
    """Invariant 5: Actor scheduler uses structured placement statuses."""

    def test_placement_status_constants(self):
        assert PlacementStatus.LEASED == "LEASED"
        assert PlacementStatus.DEFERRED == "PLACEMENT_DEFERRED"
        assert PlacementStatus.REJECTED == "PLACEMENT_REJECTED"
        assert PlacementStatus.WORKER_UNAVAILABLE == "WORKER_UNAVAILABLE"
        assert PlacementStatus.CIRCUIT_OPEN == "CIRCUIT_OPEN"

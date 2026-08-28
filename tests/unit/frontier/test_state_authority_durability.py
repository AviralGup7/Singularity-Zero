import time
import unittest

from tests.test_support.journal import MemoryJournal

from src.core.frontier.state import NeuralState
from src.core.frontier.state_authority import (
    LeaseProjection,
    SettlementCoordinator,
    StateAuthority,
    StateProjection,
)
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import ExecutionResult, Finding
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget


class TestStateAuthorityDurability(unittest.TestCase):
    def test_state_authority_commit_wal_crdt_and_deduplication(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)

        finding = Finding(
            category="sqli",
            title="SQL Injection on Login",
            severity="critical",
            confidence=0.95,
            url="https://example.com/login",
        )

        res = ExecutionResult(
            request_id="req_001",
            tenant_id="default",
            outcome="COMPLETED",
            duration_seconds=0.12,
            findings=(finding,),
            state_deltas=(
                ("subdomains", ["app.example.com"]),
                ("urls", ["https://example.com/login"]),
            ),
            execution_id="exec_unique_123",
        )

        # 1. First commit
        settle_res = authority.commit(res, stage_name="probing")
        self.assertEqual(settle_res.status, "COMMITTED")
        self.assertIsNotNone(settle_res.wal_id)
        self.assertEqual(len(wal), 1)

        # Verify CRDT state
        self.assertIn("app.example.com", state.subdomains.to_set())
        self.assertIn("https://example.com/login", state.urls.to_set())
        self.assertEqual(len(state.findings.values()), 1)
        self.assertTrue(authority.is_committed("exec_unique_123"))

        # 2. Second commit with same execution_id -> DEDUPLICATED
        dedup_res = authority.commit(res, stage_name="probing")
        self.assertEqual(dedup_res.status, "DEDUPLICATED")
        # WAL must not receive duplicate entry
        self.assertEqual(len(wal), 1)
        self.assertEqual(len(state.findings.values()), 1)

    def test_settlement_coordinator_atomic_lifecycle(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)

        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/target1", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        # Lease the target
        lease = queue.lease_batch(
            limit=1, lease_timeout_seconds=60.0, worker_id="worker_01", execution_id="exec_1"
        )[0]
        # Simulate budget reservation at gate
        enforcer.reserve_requests(1)
        self.assertEqual(enforcer.reserved_requests, 1)

        # 1. Successful execution settlement
        res = ExecutionResult(
            request_id="req_1",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_1",
            state_deltas=(("urls", ["https://example.com/target1"]),),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )

        settle_res = coordinator.settle(res, lease=lease, stage_name="probing", request_count=1)
        self.assertEqual(settle_res.status, "COMMITTED")
        self.assertEqual(enforcer.reserved_requests, 0)
        self.assertEqual(enforcer.consumed_requests, 1)

        # Target must now be acknowledged in queue
        target = queue._url_map.get("https://example.com/target1")
        self.assertTrue(target.scanned)

    def test_settlement_coordinator_failure_release(self):
        state = NeuralState()
        authority = StateAuthority(state=state)
        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/fail_target", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        lease = queue.lease_batch(
            limit=1, lease_timeout_seconds=60.0, worker_id="worker_01", execution_id="exec_fail"
        )[0]
        enforcer.reserve_requests(1)
        self.assertEqual(enforcer.reserved_requests, 1)

        # Failed execution
        fail_res = ExecutionResult(
            request_id="req_fail",
            tenant_id="default",
            outcome="FAILED",
            error="Connection refused by remote host",
            execution_id="exec_fail",
        )

        settle_res = coordinator.settle(
            fail_res, lease=lease, stage_name="probing", request_count=1
        )
        self.assertEqual(settle_res.status, "REJECTED")
        self.assertEqual(enforcer.reserved_requests, 0)
        self.assertEqual(enforcer.consumed_requests, 0)

        # Target should be released and available again
        target = queue._url_map.get("https://example.com/fail_target")
        self.assertFalse(target.scanned)
        self.assertEqual(len(queue.peek_batch(1)), 1)

    def test_wal_settlement_intent_atomic_envelope(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)

        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/target_env", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        lease = queue.lease_batch(limit=1, worker_id="worker_01", execution_id="exec_env_1")[0]
        enforcer.reserve_requests(1)

        res = ExecutionResult(
            request_id="req_env_1",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_env_1",
            state_deltas=(("urls", ["https://example.com/target_env"]),),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )

        settle_res = coordinator.settle(res, lease=lease, stage_name="probing", request_count=1)
        self.assertEqual(settle_res.status, "COMMITTED")
        self.assertEqual(len(wal), 1)

        # Inspect raw WAL record envelope
        wal_entry = wal._entries[0]
        self.assertTrue(wal_entry.get("_is_settlement_intent"))
        self.assertEqual(wal_entry.get("execution_id"), "exec_env_1")
        self.assertEqual(wal_entry.get("budget_action"), "COMMIT")
        self.assertEqual(wal_entry.get("lease_action"), "ACK")
        self.assertEqual(wal_entry.get("lease_id"), lease.lease_id)

    def test_state_projection_lag_and_wal_replay(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)

        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/target_lag", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        lease = queue.lease_batch(limit=1, worker_id="worker_01", execution_id="exec_lag_1")[0]
        enforcer.reserve_requests(1)

        # Simulate state projection failure during live dispatch
        def faulty_state_apply(intent, wal_id=None):
            raise RuntimeError("Simulated transient CRDT lock error")

        coordinator.state_projection.apply = faulty_state_apply

        res = ExecutionResult(
            request_id="req_lag_1",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_lag_1",
            state_deltas=(("urls", ["https://example.com/target_lag"]),),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )

        settle_res = coordinator.settle(res, lease=lease, stage_name="probing", request_count=1)
        self.assertEqual(settle_res.status, "COMMITTED")
        self.assertEqual(len(wal), 1)

        # CRDT does not have target yet due to simulated projection failure
        self.assertNotIn("https://example.com/target_lag", state.urls.to_set())

        # Restore state projection and replay from WAL
        coordinator.state_projection = StateProjection(state)
        coordinator.projection_engine.state_projection = coordinator.state_projection

        replayed = coordinator.replay_projections(wal)
        self.assertEqual(replayed["state"], 1)
        self.assertEqual(replayed["budget"], 0)  # Budget already applied, idempotent skip
        self.assertEqual(replayed["lease"], 0)  # Lease already applied, idempotent skip

        # CRDT is now caught up
        self.assertIn("https://example.com/target_lag", state.urls.to_set())

    def test_partially_advanced_cursors_replay(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)

        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        # Settle 3 distinct executions
        for i in range(1, 4):
            url = f"https://example.com/item_{i}"
            queue.push(ScanTarget(url=url, base_priority=float(i)))
            lease = queue.lease_batch(limit=1, worker_id="worker_01", execution_id=f"exec_{i}")[0]
            enforcer.reserve_requests(1)
            res = ExecutionResult(
                request_id=f"req_{i}",
                tenant_id="default",
                outcome="COMPLETED",
                execution_id=f"exec_{i}",
                state_deltas=(("urls", [url]),),
                findings=(
                    Finding(
                        category="test",
                        title="budget-commit",
                        severity="low",
                        confidence=0.5,
                        url="https://example.com/",
                    ),
                ),
            )
            coordinator.settle(res, lease=lease, stage_name="probing", request_count=1)

        self.assertEqual(len(wal), 3)
        self.assertEqual(enforcer.consumed_requests, 3)

        # Simulate a crash and restart where:
        # StateProjection is at offset 3
        # BudgetProjection is at offset 1
        # LeaseProjection is at offset 2
        fresh_state = NeuralState()
        fresh_budget = HuntBudgetEnforcer(budget=HuntBudget(max_requests=10))
        fresh_queue = CorrelationPriorityQueue()
        for i in range(1, 4):
            fresh_queue.push(
                ScanTarget(url=f"https://example.com/item_{i}", base_priority=float(i))
            )

        new_coord = SettlementCoordinator(
            state_authority=StateAuthority(state=fresh_state, wal=wal),
            budget_enforcer=fresh_budget,
            queue=fresh_queue,
        )

        # Pre-seed state at exec_1 and exec_2
        new_coord.state_projection.applied_execution_ids.update(["exec_1", "exec_2"])
        # Pre-seed budget at exec_1
        new_coord.budget_projection.applied_execution_ids.add("exec_1")
        fresh_budget.commit_requests(1)

        # Replay WAL
        counts = new_coord.replay_projections(wal)
        self.assertEqual(counts["state"], 1)  # only exec_3 needed
        self.assertEqual(counts["budget"], 2)  # exec_2 and exec_3 needed
        self.assertEqual(counts["lease"], 3)  # exec_1, exec_2, exec_3 needed

        self.assertEqual(fresh_budget.consumed_requests, 3)

    def test_stale_lease_during_wal_replay(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)
        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/target_stale_replay", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        # Worker 1 gets lease 1
        lease_w1 = queue.lease_batch(
            limit=1, lease_timeout_seconds=0.01, worker_id="worker_01", execution_id="exec_old"
        )[0]
        enforcer.reserve_requests(1)

        res_old = ExecutionResult(
            request_id="req_old",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_old",
            state_deltas=(("urls", ["https://example.com/target_stale_replay"]),),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )

        # Suppress queue projection for worker 1 to simulate projection lag
        coordinator.lease_projection.apply = lambda intent, wal_id=None: False
        coordinator.settle(res_old, lease=lease_w1, stage_name="probing", request_count=1)

        # Target lease expires and is re-leased to Worker 2
        target = queue._url_map.get("https://example.com/target_stale_replay")
        target.lease_expires_at = 0.0  # Force expired

        lease_w2 = queue.lease_batch(
            limit=1, lease_timeout_seconds=60.0, worker_id="worker_02", execution_id="exec_new"
        )[0]
        self.assertNotEqual(lease_w1.lease_id, lease_w2.lease_id)
        self.assertEqual(target.lease_id, lease_w2.lease_id)

        # Re-enable lease projection and replay WAL (which has worker 1's old intent)
        coordinator.lease_projection = LeaseProjection(queue)
        coordinator.projection_engine.lease_projection = coordinator.lease_projection
        coordinator.replay_projections(wal)

        # Target must remain active with Worker 2's lease, not marked scanned by Worker 1's stale lease
        self.assertFalse(target.scanned)
        self.assertEqual(target.lease_id, lease_w2.lease_id)

    def test_process_restart_cold_start_wal_reconstruction(self):
        # 1. First process run commits intents to persistent WAL
        wal = MemoryJournal()
        initial_auth = StateAuthority(state=NeuralState(), wal=wal)
        initial_budget = HuntBudgetEnforcer(budget=HuntBudget(max_requests=10))
        initial_queue = CorrelationPriorityQueue()
        initial_queue.push(ScanTarget(url="https://example.com/cold_restart", base_priority=5.0))

        initial_coord = SettlementCoordinator(
            state_authority=initial_auth,
            budget_enforcer=initial_budget,
            queue=initial_queue,
        )

        lease = initial_queue.lease_batch(
            limit=1, worker_id="worker_01", execution_id="exec_cold_1"
        )[0]
        initial_budget.reserve_requests(1)

        res = ExecutionResult(
            request_id="req_cold_1",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_cold_1",
            state_deltas=(
                ("subdomains", ["cold.example.com"]),
                ("urls", ["https://example.com/cold_restart"]),
            ),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )
        initial_coord.settle(res, lease=lease, stage_name="probing", request_count=1)

        # 2. Simulate complete cold restart (zero in-memory state)
        restarted_state = NeuralState()
        restarted_budget = HuntBudgetEnforcer(budget=HuntBudget(max_requests=10))
        restarted_queue = CorrelationPriorityQueue()
        restarted_queue.push(ScanTarget(url="https://example.com/cold_restart", base_priority=5.0))

        # Reconstruct lease on restarted queue to match
        restarted_target = restarted_queue._url_map.get("https://example.com/cold_restart")
        restarted_target.lease_id = lease.lease_id
        restarted_target.lease_expires_at = time.time() + 60.0

        restarted_coord = SettlementCoordinator(
            state_authority=StateAuthority(state=restarted_state, wal=wal),
            budget_enforcer=restarted_budget,
            queue=restarted_queue,
        )

        # Replay WAL into restarted instance
        counts = restarted_coord.replay_projections(wal)
        self.assertEqual(counts["state"], 1)
        self.assertEqual(counts["budget"], 1)
        self.assertEqual(counts["lease"], 1)

        # Check all 3 projections converged
        self.assertIn("cold.example.com", restarted_state.subdomains.to_set())
        self.assertIn("https://example.com/cold_restart", restarted_state.urls.to_set())
        self.assertEqual(restarted_budget.consumed_requests, 1)
        self.assertTrue(restarted_target.scanned)

    def test_failure_before_wal_append_no_projection_mutation(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)
        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/wal_fail_target", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        lease = queue.lease_batch(limit=1, worker_id="worker_01", execution_id="exec_walfail_1")[0]
        enforcer.reserve_requests(1)

        # Inject failure into WAL append
        def broken_append(payload):
            raise OSError("Disk full / WAL I/O error")

        wal.append = broken_append

        res = ExecutionResult(
            request_id="req_walfail_1",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_walfail_1",
            state_deltas=(("urls", ["https://example.com/wal_fail_target"]),),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )

        settle_res = coordinator.settle(res, lease=lease, stage_name="probing", request_count=1)
        self.assertEqual(settle_res.status, "REJECTED")
        self.assertIn("WAL settlement append failure", settle_res.error)

        # Invariant: No WAL entry, no CRDT state delta applied, no budget committed, no lease acked
        self.assertNotIn("https://example.com/wal_fail_target", state.urls.to_set())
        self.assertEqual(enforcer.consumed_requests, 0)
        target = queue._url_map.get("https://example.com/wal_fail_target")
        self.assertFalse(target.scanned)

    def test_duplicate_replay_is_strictly_noop(self):
        state = NeuralState()
        wal = MemoryJournal()
        authority = StateAuthority(state=state, wal=wal)
        budget = HuntBudget(max_requests=10)
        enforcer = HuntBudgetEnforcer(budget=budget)
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://example.com/dup_target", base_priority=5.0))

        coordinator = SettlementCoordinator(
            state_authority=authority,
            budget_enforcer=enforcer,
            queue=queue,
        )

        lease = queue.lease_batch(limit=1, worker_id="worker_01", execution_id="exec_dup_1")[0]
        enforcer.reserve_requests(1)

        res = ExecutionResult(
            request_id="req_dup_1",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_dup_1",
            state_deltas=(("urls", ["https://example.com/dup_target"]),),
            findings=(
                Finding(
                    category="test",
                    title="budget-commit",
                    severity="low",
                    confidence=0.5,
                    url="https://example.com/",
                ),
            ),
        )
        coordinator.settle(res, lease=lease, stage_name="probing", request_count=1)

        # First replay
        replayed_1 = coordinator.replay_projections(wal)
        self.assertEqual(replayed_1["state"], 0)
        self.assertEqual(replayed_1["budget"], 0)
        self.assertEqual(replayed_1["lease"], 0)

        # Second replay
        replayed_2 = coordinator.replay_projections(wal)
        self.assertEqual(replayed_2["state"], 0)
        self.assertEqual(replayed_2["budget"], 0)
        self.assertEqual(replayed_2["lease"], 0)

        # Consumed requests strictly remains 1
        self.assertEqual(enforcer.consumed_requests, 1)

import unittest

from src.core.frontier.state import NeuralState
from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import CandidateLease, ExecutionResult, Finding
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget
from src.frontier.journal import MemoryJournal


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
            state_deltas=(("subdomains", ["app.example.com"]), ("urls", ["https://example.com/login"])),
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
        lease = queue.lease_batch(limit=1, lease_timeout_seconds=60.0, worker_id="worker_01", execution_id="exec_1")[0]
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

        lease = queue.lease_batch(limit=1, lease_timeout_seconds=60.0, worker_id="worker_01", execution_id="exec_fail")[0]
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

        settle_res = coordinator.settle(fail_res, lease=lease, stage_name="probing", request_count=1)
        self.assertEqual(settle_res.status, "REJECTED")
        self.assertEqual(enforcer.reserved_requests, 0)
        self.assertEqual(enforcer.consumed_requests, 0)

        # Target should be released and available again
        target = queue._url_map.get("https://example.com/fail_target")
        self.assertFalse(target.scanned)
        self.assertEqual(len(queue.peek_batch(1)), 1)

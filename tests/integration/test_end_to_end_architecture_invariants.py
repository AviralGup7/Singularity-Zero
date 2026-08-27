"""End-to-End Architectural Invariants Integration Test Suite.

Proves the complete 7-layer control chain and State Authority boundary:
1. Priority Queue -> Candidate Lease binding
2. Dispatcher -> ExecutionRequest contract of intent
3. Authorization Gate -> Scope validation + Atomic Budget reservation + HMAC Ticket
4. Stateless Worker -> Ticket consumption + ExecutionResult identity propagation
5. Settlement Coordinator -> StateAuthority (WAL -> CRDT -> ExecID) + Budget Commit + Lease Ack
6. Invariant protections -> Replay rejection, Stale Lease rejection, Budget exhaustion enforcement
"""

import time
import unittest

from src.core.frontier.state import NeuralState
from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
from src.decision.authorization import ExecutionAuthorizer, ScopeAuthorizationError
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import (
    ActionSpec,
    ExecutionRequest,
    ExecutionResult,
    Finding,
    ResourceLimits,
    ScopeToken,
    TargetSpec,
)
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget
from src.execution.request_executor import ExecutionRequestWorker
from tests.test_support.journal import MemoryJournal


class TestEndToEndArchitectureInvariants(unittest.TestCase):
    def setUp(self):
        self.state = NeuralState()
        self.wal = MemoryJournal()
        self.state_authority = StateAuthority(state=self.state, wal=self.wal)
        self.budget = HuntBudget(max_requests=5)
        self.budget_enforcer = HuntBudgetEnforcer(budget=self.budget)
        self.queue = CorrelationPriorityQueue()
        self.authorizer = ExecutionAuthorizer(budget_enforcer=self.budget_enforcer)
        self.worker = ExecutionRequestWorker(authorizer=self.authorizer)
        self.settlement = SettlementCoordinator(
            state_authority=self.state_authority,
            budget_enforcer=self.budget_enforcer,
            queue=self.queue,
        )

    def test_complete_end_to_end_execution_and_settlement_chain(self):
        # 1. Enqueue Target
        self.queue.push(
            ScanTarget(
                url="https://api.target.com/v1/auth",
                base_priority=80.0,
            )
        )

        # 2. Priority Engine leases target with CandidateLease
        leases = self.queue.lease_batch(
            limit=1,
            lease_timeout_seconds=60.0,
            worker_id="worker_alpha",
            execution_id="exec_cycle_01",
        )
        self.assertEqual(len(leases), 1)
        lease = leases[0]
        self.assertEqual(lease.target_url, "https://api.target.com/v1/auth")
        self.assertTrue(lease.lease_id.startswith("lease_"))

        # 3. Dispatcher builds ExecutionRequest with identity binding
        finding_payload = {
            "category": "auth_bypass",
            "title": "Broken Object Level Authentication",
            "severity": "high",
            "confidence": 0.92,
            "url": lease.target_url,
        }
        action = ActionSpec(
            action_id="act_probe_auth",
            action_type="probe",
            tool_or_detector="auth_fuzzer",
            payload=(("emits_finding", True), ("finding", finding_payload)),
        )

        req = ExecutionRequest(
            request_id="req_cycle_01",
            tenant_id="tenant_alpha",
            target=TargetSpec(host="api.target.com", path="/v1/auth"),
            stage="probing",
            actions=(action,),
            scope_token=ScopeToken(scope_hash="h_scope", allowed_domains=("api.target.com",)),
            resource_limits=ResourceLimits(timeout_seconds=30.0),
            deadline=time.time() + 60.0,
            execution_id="exec_cycle_01",
            job_id="job_omega",
            candidate_id=lease.candidate_id,
            lease_id=lease.lease_id,
        )

        # 4. Authorization Gate admits request, reserves budget, and issues ticket
        ticket = self.authorizer.authorize(req)
        self.assertIsNotNone(ticket)
        self.assertEqual(self.budget_enforcer.reserved_requests, 1)

        # 5. Worker consumes ticket (single-use) and returns ExecutionResult
        result = self.worker.execute(ticket)
        self.assertEqual(result.outcome, "COMPLETED")
        self.assertEqual(result.execution_id, "exec_cycle_01")
        self.assertEqual(result.candidate_id, lease.candidate_id)
        self.assertEqual(result.lease_id, lease.lease_id)
        self.assertEqual(len(result.findings), 1)

        # 6. Settlement Coordinator settles state, budget, and lease
        settle_result = self.settlement.settle(
            result=result,
            lease=lease,
            stage_name="probing",
            request_count=1,
        )

        self.assertEqual(settle_result.status, "COMMITTED")
        self.assertIsNotNone(settle_result.wal_id)
        self.assertEqual(self.budget_enforcer.reserved_requests, 0)
        self.assertEqual(self.budget_enforcer.consumed_requests, 1)

        # Verify state committed into CRDT
        self.assertEqual(len(self.state.findings.values()), 1)
        self.assertTrue(self.state_authority.is_committed("exec_cycle_01"))

        # Verify candidate lease acknowledged in queue
        target = self.queue._url_map.get("https://api.target.com/v1/auth")
        self.assertIsNotNone(target)
        self.assertTrue(target.scanned)

    def test_invariant_ticket_replay_rejection(self):
        req = ExecutionRequest(
            request_id="req_replay",
            tenant_id="default",
            target=TargetSpec(host="api.target.com"),
            stage="probing",
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("api.target.com",)),
            execution_id="exec_rep",
        )
        ticket = self.authorizer.authorize(req)

        # First execution consumes nonce
        res1 = self.worker.execute(ticket)
        self.assertEqual(res1.outcome, "COMPLETED")

        # Second execution replay MUST be rejected
        res2 = self.worker.execute(ticket)
        self.assertEqual(res2.outcome, "REJECTED")
        self.assertIn("failed consumption", res2.error)

    def test_invariant_state_authority_execution_id_deduplication(self):
        res = ExecutionResult(
            request_id="req_dup",
            tenant_id="default",
            outcome="COMPLETED",
            execution_id="exec_dedup_99",
            findings=(
                Finding(
                    category="xss",
                    title="Stored XSS",
                    severity="high",
                    confidence=0.9,
                    url="https://api.target.com/comments",
                ),
            ),
        )

        res1 = self.state_authority.commit(res)
        self.assertEqual(res1.status, "COMMITTED")
        self.assertEqual(len(self.state.findings.values()), 1)
        self.assertEqual(len(self.wal), 1)

        # Duplicate commit MUST be marked DEDUPLICATED and avoid double-writing to WAL/CRDT
        res2 = self.state_authority.commit(res)
        self.assertEqual(res2.status, "DEDUPLICATED")
        self.assertEqual(len(self.state.findings.values()), 1)
        self.assertEqual(len(self.wal), 1)

    def test_invariant_stale_worker_lease_ack_rejected(self):
        self.queue.push(ScanTarget(url="https://api.target.com/item", base_priority=10.0))

        # Worker A gets short lease
        lease_a = self.queue.lease_batch(limit=1, lease_timeout_seconds=0.04, worker_id="worker_A")[
            0
        ]
        time.sleep(0.05)

        # Worker B gets renewed lease
        lease_b = self.queue.lease_batch(limit=1, lease_timeout_seconds=60.0, worker_id="worker_B")[
            0
        ]

        # Worker A attempts to ack -> rejected
        acked = self.queue.ack_batch([lease_a])
        self.assertEqual(acked, 0)

        # Worker B acks -> accepted
        acked_b = self.queue.ack_batch([lease_b])
        self.assertEqual(acked_b, 1)

    def test_invariant_budget_capacity_exhaustion_admission_block(self):
        # max_requests is 5 in setUp
        for i in range(5):
            r = ExecutionRequest(
                request_id=f"req_fill_{i}",
                tenant_id="default",
                target=TargetSpec(host="api.target.com"),
                stage="probing",
                scope_token=ScopeToken(scope_hash="h1", allowed_domains=("api.target.com",)),
            )
            self.authorizer.authorize(r)

        self.assertEqual(self.budget_enforcer.available_requests, 0)

        # 6th request MUST be rejected by Authorization Gate
        excess_req = ExecutionRequest(
            request_id="req_excess",
            tenant_id="default",
            target=TargetSpec(host="api.target.com"),
            stage="probing",
            scope_token=ScopeToken(scope_hash="h1", allowed_domains=("api.target.com",)),
        )
        with self.assertRaises(ScopeAuthorizationError):
            self.authorizer.authorize(excess_req)

    def test_invariant_worker_rejects_raw_unauthorized_request(self):
        raw_req = ExecutionRequest(
            request_id="req_bypass",
            tenant_id="default",
            target=TargetSpec(host="api.target.com"),
            stage="probing",
        )
        res = self.worker.execute(raw_req)  # type: ignore[arg-type]
        self.assertEqual(res.outcome, "REJECTED")
        self.assertIn("Worker strictly requires an AuthorizedExecutionTicket", res.error)

    def test_invariant_stage_output_settlement_through_coordinator(self):
        from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
        from src.core.models.stage_result import PipelineContext

        ctx = PipelineContext()
        stage_out = StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=1.2,
            state_delta={"subdomains": ["api.example.com", "app.example.com"]},
            metrics={"discovered_count": 2},
        )

        settle_res = self.settlement.settle_stage_output(ctx, "subdomains", stage_out)
        self.assertEqual(settle_res.status, "COMMITTED")
        self.assertIn("api.example.com", ctx.result.subdomains)
        self.assertIn("app.example.com", ctx.result.subdomains)
        self.assertEqual(str(ctx.result.stage_status.get("subdomains")).upper(), "COMPLETED")

    def test_invariant_priority_engine_versioned_policy_scoring(self):
        from src.learning.versioned_policy import VersionedPolicy

        policy = VersionedPolicy(
            policy_id="pol_v2",
            version="2.0.0",
            target_boosts=(("https://api.target.com/v1/auth", 50.0),),
            target_suppressions=(("https://api.target.com/logout", -20.0),),
        )

        pq = CorrelationPriorityQueue(policy=policy)
        pq.push(ScanTarget(url="https://api.target.com/v1/auth", base_priority=10.0))
        pq.push(ScanTarget(url="https://api.target.com/other", base_priority=10.0))

        # Target matching boost should have higher effective priority
        peeked = pq.peek_batch(limit=2)
        self.assertEqual(peeked[0], "https://api.target.com/v1/auth")
        self.assertEqual(pq.policy_version, "2.0.0")

    def test_invariant_scanner_tool_execution_under_contract(self):
        import asyncio

        from src.pipeline.services.pipeline_orchestrator.stages._tool_runner import run_scanner

        async def _run():
            return await run_scanner(["python", "--version"], timeout=5)

        res = asyncio.run(_run())
        self.assertEqual(res.returncode, 0)
        self.assertTrue(len(res.stdout) > 0 or len(res.stderr) > 0)

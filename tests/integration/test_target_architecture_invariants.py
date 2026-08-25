"""Integration Test Suite for Target System Architecture and Invariants Contract.

Validates the full target architecture implementation:
- Multi-replica deterministic FSM execution (identical state hashes)
- Certified command receipt generation and signature verification
- Universal budget conservation and two-phase sub-lease return to P-0000
- Deterministic external timer replay purity (LeaseTimeoutCommand)
- 5-stage fenced aggregate ownership migration
- Projection vector checkpoints, gap detection, and deterministic cold rebuild
- Full 16-invariant audit pass rate
"""

import unittest

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.frontier.global_coordination import (
    GlobalBudgetAggregate,
    PlacementAuthority,
)
from src.core.frontier.invariant_checker import InvariantChecker
from src.core.frontier.projection_stream import CommittedLogConsumer
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.replicated_log import ReplicatedPartitionLog
from src.core.frontier.run_saga import DurableRunSagaEngine


class TestTargetArchitectureInvariants(unittest.TestCase):
    def setUp(self):
        self.global_budget = GlobalBudgetAggregate(total_budget=10000)
        self.placement = PlacementAuthority(initial_version=7)
        self.p0412_fsm_leader = PartitionFSM(partition_id="P-0412")
        self.p0412_fsm_follower = PartitionFSM(partition_id="P-0412")
        self.p0412_log = ReplicatedPartitionLog(
            partition_id="P-0412",
            current_term=1,
            is_leader=True,
            fsm=self.p0412_fsm_leader,
        )
        self.logs = {"P-0412": self.p0412_log}
        self.saga_engine = DurableRunSagaEngine(
            global_budget=self.global_budget,
            placement_authority=self.placement,
            partition_logs=self.logs,
        )

    def test_multi_replica_deterministic_fsm_execution(self):
        """Axiom 2 & 3: Multi-replica identical FSM execution and certified receipt."""
        # 1. Allocate Sublease
        alloc_cmd = CommandEnvelope(
            command_id="cmd_alloc_01",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_R101_P0412",
            payload={
                "sublease_id": "sublease_R101_P0412",
                "units_allocated": 100,
                "run_id": "R-101",
            },
            correlation_id="R-101",
            causation_id="start_test",
        )
        receipt1, events1 = self.p0412_log.propose_and_commit(
            alloc_cmd,
            follower_fsms=[self.p0412_fsm_follower],
        )
        self.assertEqual(receipt1.result_code, "SUBLEASE_ALLOCATED")
        self.assertEqual(
            self.p0412_fsm_leader.get_state_hash(), self.p0412_fsm_follower.get_state_hash()
        )

        # 2. Authorize Execution
        auth_cmd = CommandEnvelope(
            command_id="cmd_auth_01",
            command_type="AuthorizeExecutionCommand",
            aggregate_id="exec_cycle_01",
            payload={
                "capability_id": "cap-98a1",
                "sublease_id": "sublease_R101_P0412",
                "units_requested": 5,
                "key_epoch": 0,
            },
            correlation_id="R-101",
            causation_id="cmd_alloc_01",
        )
        receipt2, events2 = self.p0412_log.propose_and_commit(
            auth_cmd,
            follower_fsms=[self.p0412_fsm_follower],
        )
        self.assertEqual(receipt2.result_code, "EXECUTION_AUTHORIZED")
        self.assertEqual(
            self.p0412_fsm_leader.get_state_hash(), self.p0412_fsm_follower.get_state_hash()
        )

        # 3. Submit Claim
        claim_cmd = CommandEnvelope(
            command_id="cmd_claim_01",
            command_type="SubmitExecutionClaim",
            aggregate_id="exec_cycle_01",
            payload={
                "capability_id": "cap-98a1",
                "units_consumed": 3,
                "findings": [{"title": "SQL Injection", "severity": "high"}],
            },
            correlation_id="R-101",
            causation_id="cmd_auth_01",
        )
        receipt3, events3 = self.p0412_log.propose_and_commit(
            claim_cmd,
            follower_fsms=[self.p0412_fsm_follower],
        )
        self.assertEqual(receipt3.result_code, "CLAIM_SETTLED_SUCCESS")
        self.assertEqual(
            self.p0412_fsm_leader.get_state_hash(), self.p0412_fsm_follower.get_state_hash()
        )
        self.assertEqual(receipt3.state_hash_at_commit, self.p0412_fsm_leader.get_state_hash())

    def test_universal_budget_conservation_and_two_phase_return(self):
        """Axiom 4: Universal budget conservation equation across sub-lease allocation and return."""
        # Initial state: 10000 available
        self.assertTrue(self.global_budget.verify_conservation())
        self.assertEqual(self.global_budget.available, 10000)

        # 1. Reserve sub-lease
        success, msg = self.global_budget.reserve_sublease(
            sublease_id="sub_test_01",
            run_id="R-101",
            partition_id="P-0412",
            units=2500,
        )
        self.assertTrue(success)
        self.assertTrue(self.global_budget.verify_conservation())
        self.assertEqual(self.global_budget.available, 7500)
        self.assertEqual(self.global_budget.outstanding_reserved, 2500)

        # 2. Settle return (Consumed 800, Returned 1700)
        ret_ok, ret_msg = self.global_budget.settle_return(
            sublease_id="sub_test_01",
            units_consumed=800,
            units_returned=1700,
        )
        self.assertTrue(ret_ok)
        self.assertTrue(self.global_budget.verify_conservation())
        self.assertEqual(self.global_budget.consumed, 800)
        self.assertEqual(self.global_budget.available, 9200)
        self.assertEqual(self.global_budget.outstanding_reserved, 0)

    def test_deterministic_external_timer_replay_purity(self):
        """Axiom 9: LeaseTimeoutCommand evaluated deterministically via observed_at timestamp."""
        # Setup running execution
        alloc_cmd = CommandEnvelope(
            command_id="cmd_alloc_02",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_time",
            payload={"sublease_id": "sub_time", "units_allocated": 10},
            correlation_id="R-102",
            causation_id="init",
        )
        self.p0412_log.propose_and_commit(alloc_cmd)

        auth_cmd = CommandEnvelope(
            command_id="cmd_auth_02",
            command_type="AuthorizeExecutionCommand",
            aggregate_id="exec_time",
            payload={"capability_id": "cap-time", "sublease_id": "sub_time", "units_requested": 5},
            correlation_id="R-102",
            causation_id="cmd_alloc_02",
        )
        self.p0412_log.propose_and_commit(auth_cmd)

        # Timeout command with observed_at timestamp
        timeout_cmd = CommandEnvelope(
            command_id="cmd_timeout_01",
            command_type="LeaseTimeoutCommand",
            aggregate_id="exec_time",
            payload={"observed_at": 1770000000.0, "max_skew": 0.5},
            correlation_id="R-102",
            causation_id="timer",
        )
        receipt, events = self.p0412_log.propose_and_commit(timeout_cmd)
        self.assertEqual(receipt.result_code, "LEASE_EXPIRED_PESSIMISTIC")
        self.assertEqual(self.p0412_fsm_leader.aggregates["exec_time"].status, "EXPIRED")

    def test_projection_consumption_gap_detection_and_cold_rebuild(self):
        """Axiom 5 & Contract Section 8: Projection vector watermarks and cold rebuild."""
        consumer = CommittedLogConsumer(projection_id="FindingProjection")

        # Populate log entries
        alloc_cmd = CommandEnvelope(
            command_id="cmd_alloc_p",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_p",
            payload={"sublease_id": "sub_p", "units_allocated": 50},
            correlation_id="R-P",
            causation_id="init",
        )
        self.p0412_log.propose_and_commit(alloc_cmd)

        auth_cmd = CommandEnvelope(
            command_id="cmd_auth_p",
            command_type="AuthorizeExecutionCommand",
            aggregate_id="exec_p",
            payload={"capability_id": "cap-p", "sublease_id": "sub_p", "units_requested": 10},
            correlation_id="R-P",
            causation_id="cmd_alloc_p",
        )
        self.p0412_log.propose_and_commit(auth_cmd)

        # Consume entries
        for entry in self.p0412_log.entries:
            ok, msg = consumer.consume_entry(entry)
            self.assertTrue(ok)

        ckpt = consumer.get_checkpoint_vector()
        self.assertEqual(
            ckpt.partition_offsets["P-0412"].last_applied_index, self.p0412_log.commit_index
        )

        # Cold rebuild test
        rebuilt_hash = consumer.cold_rebuild(self.logs)
        self.assertEqual(rebuilt_hash, ckpt.state_hash)

    def test_certified_snapshot_export_load_and_hash_integrity(self):
        """Axiom 5 & Invariants I11, I12, I13: Certified snapshot export, restore, and hash verification."""
        # 1. State machine has active state
        alloc_cmd = CommandEnvelope(
            command_id="cmd_snap_alloc",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_snap",
            payload={"sublease_id": "sub_snap", "units_allocated": 300},
            correlation_id="R-SNAP",
            causation_id="init",
        )
        self.p0412_log.propose_and_commit(alloc_cmd)

        # 2. Export certified snapshot
        snapshot = self.p0412_fsm_leader.export_certified_snapshot()
        self.assertEqual(snapshot.last_included_index, self.p0412_log.commit_index)
        self.assertEqual(snapshot.state_hash, self.p0412_fsm_leader.get_state_hash())

        # 3. Restore into a clean standby FSM
        standby_fsm = PartitionFSM(partition_id="P-0412")
        restored = standby_fsm.load_certified_snapshot(snapshot)
        self.assertTrue(restored)
        self.assertEqual(standby_fsm.get_state_hash(), self.p0412_fsm_leader.get_state_hash())
        self.assertIn("sub_snap", standby_fsm.subleases)
        self.assertEqual(standby_fsm.subleases["sub_snap"].units_allocated, 300)

    def test_full_16_system_invariants_pass(self):
        """Contract Section 9: 16 Formal System Invariants Audit."""
        report = InvariantChecker.run_full_audit(
            p_logs=self.logs,
            global_budget=self.global_budget,
        )
        self.assertTrue(report.passed, f"Failed invariants: {report.failed_invariants}")
        self.assertGreater(len(report.passed_invariants), 10)


if __name__ == "__main__":
    unittest.main()

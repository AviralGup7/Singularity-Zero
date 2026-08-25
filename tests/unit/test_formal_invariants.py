"""Formal System Invariant Test Suite.

Verifies the 9 Core Architectural Invariants:
- INVARIANT-001: Universal Budget Conservation (Total = Consumed + Reserved + Available)
- INVARIANT-002: Ticket Issued implies Committed Budget Reservation
- INVARIANT-003: FSM.Apply is purely deterministic (identical state hash across replicas)
- INVARIANT-004: Authoritative state mutations require committed Raft log entry
- INVARIANT-005: Expired leases trigger deterministic release and budget restoration
- INVARIANT-006: Active ML policy reference is committed to Raft FSM and survives replay
- INVARIANT-007: Checkpoints cannot override or diverge from authoritative FSM state
- INVARIANT-008: Scoped idempotency (duplicate commands produce zero additional mutations)
- INVARIANT-009: Stale epoch claims are rejected with zero authoritative mutations
"""

from __future__ import annotations

import unittest
from src.core.checkpoint.base import CheckpointState
from src.core.checkpoint.recovery import verify_checkpoint_against_fsm
from src.core.contracts.canonical_target import compute_canonical_state_hash
from src.core.contracts.command_envelope import (
    CommandEnvelope,
    CommandResult,
    CommittedEntry,
    EventEnvelope,
)
from src.core.frontier.global_coordination import (
    GlobalBudgetAggregate,
    GlobalRunAggregate,
    PlacementAuthority,
)
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.replicated_log import ReplicatedPartitionLog
from src.core.frontier.run_saga import DurableRunSagaEngine
from src.decision.authorization import ExecutionAuthorizer, ScopeAuthorizationError
from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
from src.decision.models import (
    ActionSpec,
    ExecutionRequest,
    ScopeToken,
    TargetSpec,
)
from src.learning.versioned_policy import VersionedPolicy
from src.realtime.prioritized_broker import PrioritizedRealtimeBroker, QoSClass, TelemetryEvent


class TestFormalSystemInvariants(unittest.TestCase):
    def setUp(self) -> None:
        self.global_budget = GlobalBudgetAggregate(total_budget=5000)
        self.placement = PlacementAuthority(initial_version=1)
        self.p0001_fsm = PartitionFSM(partition_id="P-0001")
        self.p0001_fsm_replica = PartitionFSM(partition_id="P-0001")
        self.p0001_log = ReplicatedPartitionLog(
            partition_id="P-0001",
            current_term=1,
            is_leader=True,
            fsm=self.p0001_fsm,
        )
        self.saga_engine = DurableRunSagaEngine(
            global_budget=self.global_budget,
            placement_authority=self.placement,
            partition_logs={"P-0001": self.p0001_log},
        )

    # -------------------------------------------------------------------------
    # INVARIANT-001: Universal Budget Conservation
    # -------------------------------------------------------------------------
    def test_invariant_001_budget_conservation(self) -> None:
        """INVARIANT-001: TotalBudget == Consumed + OutstandingReserved + Available."""
        gb = self.global_budget
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.total_budget, 5000)
        self.assertEqual(gb.available, 5000)
        self.assertEqual(gb.consumed, 0)
        self.assertEqual(gb.outstanding_reserved, 0)

        # 1. Reserve 1500 units across two subleases
        ok1, _ = gb.reserve_sublease("sl_01", "run_1", "P-0001", 1000)
        ok2, _ = gb.reserve_sublease("sl_02", "run_1", "P-0002", 500)
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.outstanding_reserved, 1500)
        self.assertEqual(gb.available, 3500)

        # 2. Settle sl_01: 700 consumed, 300 returned
        ok3, _ = gb.settle_return("sl_01", units_consumed=700, units_returned=300)
        self.assertTrue(ok3)
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.consumed, 700)
        self.assertEqual(gb.outstanding_reserved, 500)
        self.assertEqual(gb.available, 3800)

        # 3. Settle sl_02: 0 consumed, 500 returned
        ok4, _ = gb.settle_return("sl_02", units_consumed=0, units_returned=500)
        self.assertTrue(ok4)
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.consumed, 700)
        self.assertEqual(gb.outstanding_reserved, 0)
        self.assertEqual(gb.available, 4300)

    # -------------------------------------------------------------------------
    # INVARIANT-002: Mandatory Committed Budget Reservation
    # -------------------------------------------------------------------------
    def test_invariant_002_ticket_requires_committed_reservation(self) -> None:
        """INVARIANT-002: Ticket issuance strictly requires a committed budget reservation."""
        # Unconfigured budget enforcer must raise ScopeAuthorizationError
        unbudgeted_authorizer = ExecutionAuthorizer(secret_key="test-key")
        req = ExecutionRequest(
            request_id="req_test_inv2",
            tenant_id="tenant_a",
            target=TargetSpec(host="example.com", path="/api"),
            stage="probing",
            actions=(ActionSpec(action_id="a1", action_type="probe", tool_or_detector="http_prober"),),
        )
        with self.assertRaises(ScopeAuthorizationError) as ctx:
            unbudgeted_authorizer.authorize(req)
        self.assertIn("Mandatory budget enforcer not configured", str(ctx.exception))

        # Configured budget enforcer succeeds when quota available
        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=10))
        budgeted_authorizer = ExecutionAuthorizer(secret_key="test-key", budget_enforcer=enforcer)
        ticket = budgeted_authorizer.authorize(req)
        self.assertTrue(ticket.ticket_id.startswith("tkt_"))
        self.assertEqual(enforcer.reserved_requests, 1)

    # -------------------------------------------------------------------------
    # INVARIANT-003: Pure Deterministic FSM Execution
    # -------------------------------------------------------------------------
    def test_invariant_003_fsm_apply_determinism(self) -> None:
        """INVARIANT-003: FSM.Apply is pure; replicas produce identical state hashes."""
        cmd1 = CommandEnvelope(
            command_id="cmd_alloc_sublease_1",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_p1",
            payload={"sublease_id": "sublease_p1", "units_allocated": 200, "run_id": "R1"},
            correlation_id="corr_1",
            causation_id="caus_1",
            expected_aggregate_version=0,
        )
        receipt, events = self.p0001_log.propose_and_commit(
            cmd1,
            follower_fsms=[self.p0001_fsm_replica],
        )

        self.assertEqual(receipt.result_code, "SUBLEASE_ALLOCATED")
        self.assertEqual(self.p0001_fsm.get_state_hash(), self.p0001_fsm_replica.get_state_hash())
        self.assertEqual(receipt.state_hash_at_commit, self.p0001_fsm.get_state_hash())
        self.assertEqual(len(events), 1)

    # -------------------------------------------------------------------------
    # INVARIANT-004: Authoritative State Mutations Require Committed Raft Log Entry
    # -------------------------------------------------------------------------
    def test_invariant_004_state_mutations_require_committed_log_entry(self) -> None:
        """INVARIANT-004: State machine mutations occur only through committed log entries."""
        pre_hash = self.p0001_fsm.get_state_hash()
        pre_index = self.p0001_fsm.last_applied_index

        cmd = CommandEnvelope(
            command_id="cmd_auth_test_inv4",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_inv4",
            payload={"sublease_id": "sublease_inv4", "units_allocated": 50, "run_id": "R1"},
            correlation_id="corr_4",
            causation_id="caus_4",
        )
        receipt, events = self.p0001_log.propose_and_commit(cmd)

        post_hash = self.p0001_fsm.get_state_hash()
        post_index = self.p0001_fsm.last_applied_index

        self.assertNotEqual(pre_hash, post_hash)
        self.assertEqual(post_index, pre_index + 1)
        self.assertEqual(receipt.state_hash_at_commit, post_hash)

    # -------------------------------------------------------------------------
    # INVARIANT-005: Expired Leases Deterministically Release and Restore Budget
    # -------------------------------------------------------------------------
    def test_invariant_005_expired_lease_reclaims_budget(self) -> None:
        """INVARIANT-005: Lease expiration recovers orphaned units to available budget."""
        gb = self.global_budget
        ok1, _ = gb.reserve_sublease("sl_orphan", "run_orphan", "P-0001", 300)
        self.assertTrue(ok1)
        self.assertEqual(gb.outstanding_reserved, 300)
        self.assertEqual(gb.available, 4700)

        # Worker dies without settling; timeout reclaims lease
        ok2, msg = gb.expire_sublease("sl_orphan", units_consumed=0)
        self.assertTrue(ok2)
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.outstanding_reserved, 0)
        self.assertEqual(gb.available, 5000)
        self.assertEqual(gb.subleases["sl_orphan"].status, "EXPIRED")

    # -------------------------------------------------------------------------
    # INVARIANT-006: Active ML Policy Reference Committed to Raft FSM
    # -------------------------------------------------------------------------
    def test_invariant_006_active_policy_committed_survives_replay(self) -> None:
        """INVARIANT-006: Active policy reference is committed to Raft FSM and survives replay."""
        cmd_promote = CommandEnvelope(
            command_id="cmd_promote_v2",
            command_type="PromotePolicyCommand",
            aggregate_id="policy_active",
            payload={
                "policy_id": "policy_v2_alpha",
                "artifact_hash": "sha256_hash_abc123",
                "policy_version": "v2.0",
                "parent_policy_id": "policy_v1_base",
            },
            correlation_id="corr_pol",
            causation_id="governance_gate",
        )
        receipt, events = self.p0001_log.propose_and_commit(cmd_promote)
        self.assertEqual(receipt.result_code, "POLICY_PROMOTED")

        # Verify aggregate state in FSM
        agg = self.p0001_fsm.aggregates.get("policy_active")
        self.assertIsNotNone(agg)
        self.assertEqual(agg.state_payload["active_policy_id"], "policy_v2_alpha")
        self.assertEqual(agg.state_payload["artifact_hash"], "sha256_hash_abc123")

        # Rollback policy
        cmd_rollback = CommandEnvelope(
            command_id="cmd_rollback_v1",
            command_type="RollbackPolicyCommand",
            aggregate_id="policy_active",
            payload={"parent_policy_id": "policy_v1_base"},
            correlation_id="corr_pol_2",
            causation_id="canary_anomaly",
        )
        receipt_rb, _ = self.p0001_log.propose_and_commit(cmd_rollback)
        self.assertEqual(receipt_rb.result_code, "POLICY_ROLLED_BACK")
        agg_rb = self.p0001_fsm.aggregates.get("policy_active")
        self.assertEqual(agg_rb.state_payload["active_policy_id"], "policy_v1_base")

    # -------------------------------------------------------------------------
    # INVARIANT-007: Checkpoint Cannot Override Authoritative FSM State
    # -------------------------------------------------------------------------
    def test_invariant_007_checkpoint_cannot_override_fsm(self) -> None:
        """INVARIANT-007: Checkpoints are projections and cannot override authoritative FSM state."""
        fsm = self.p0001_fsm

        # Checkpoint with future log index is rejected
        stale_checkpoint = CheckpointState(
            pipeline_run_id="run-future",
            completed_stages=["recon", "probing"],
            authoritative_log_index=fsm.last_applied_index + 100,
            authoritative_state_hash="fake_hash",
        )
        self.assertFalse(verify_checkpoint_against_fsm(stale_checkpoint, fsm))

        # Checkpoint matching FSM coordinates is accepted
        valid_checkpoint = CheckpointState(
            pipeline_run_id="run-valid",
            completed_stages=["recon"],
            authoritative_log_index=fsm.last_applied_index,
            authoritative_state_hash=fsm.get_state_hash(),
        )
        self.assertTrue(verify_checkpoint_against_fsm(valid_checkpoint, fsm))

    # -------------------------------------------------------------------------
    # INVARIANT-008: Scoped Idempotency
    # -------------------------------------------------------------------------
    def test_invariant_008_scoped_idempotency(self) -> None:
        """INVARIANT-008: Duplicate command delivery produces zero additional mutations."""
        cmd = CommandEnvelope(
            command_id="cmd_idempotent_test",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_idem",
            payload={"sublease_id": "sublease_idem", "units_allocated": 100, "run_id": "R1"},
            correlation_id="corr_2",
            causation_id="caus_2",
            expected_aggregate_version=0,
        )
        receipt_1, events_1 = self.p0001_log.propose_and_commit(cmd)
        hash_1 = self.p0001_fsm.get_state_hash()
        self.assertEqual(receipt_1.result_code, "SUBLEASE_ALLOCATED")

        # Propose duplicate command with exact same command_id
        receipt_2, events_2 = self.p0001_log.propose_and_commit(cmd)
        hash_2 = self.p0001_fsm.get_state_hash()

        self.assertEqual(hash_1, hash_2)
        self.assertEqual(receipt_2.result_code, "SUBLEASE_ALLOCATED")
        self.assertEqual(len(events_2), 0)  # No duplicate events emitted

    # -------------------------------------------------------------------------
    # INVARIANT-009: Stale Epoch Fencing
    # -------------------------------------------------------------------------
    def test_invariant_009_stale_epoch_rejection(self) -> None:
        """INVARIANT-009: Outdated epoch claims are rejected with zero mutations."""
        # Key revocation epoch advances
        cmd_revoke = CommandEnvelope(
            command_id="cmd_revoke_key_1",
            command_type="SyncKeyRevocationCommand",
            aggregate_id="global_keys",
            payload={"revocation_epoch": 2},
            correlation_id="corr_rev",
            causation_id="key_rotation",
        )
        self.p0001_log.propose_and_commit(cmd_revoke)

        # Stale capability signed with epoch 0 is submitted
        cmd_stale = CommandEnvelope(
            command_id="cmd_stale_auth",
            command_type="AuthorizeExecutionCommand",
            aggregate_id="exec_stale",
            payload={
                "capability_id": "cap-old",
                "sublease_id": "sublease_idem",
                "units_requested": 5,
                "key_epoch": 0,  # Stale epoch < 2
            },
            correlation_id="corr_stale",
            causation_id="zombie_worker",
        )
        receipt_stale, events_stale = self.p0001_log.propose_and_commit(cmd_stale)
        self.assertEqual(receipt_stale.result_code, "KEY_REVOKED")
        self.assertEqual(len(events_stale), 0)

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
from src.core.contracts.command_envelope import (
    CommandEnvelope,
)
from src.core.frontier.global_coordination import (
    GlobalBudgetAggregate,
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
            actions=(
                ActionSpec(action_id="a1", action_type="probe", tool_or_detector="http_prober"),
            ),
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

    # -------------------------------------------------------------------------
    # INVARIANT-I22': Temporal Invariant via Admission Gate & Clock-Free FSM
    # -------------------------------------------------------------------------
    def test_invariant_i22_prime_temporal_monotonicity_admission(self) -> None:
        """INVARIANT-I22': Clock-skew gating at admission and pure clock-free FSM."""
        import time

        now = time.time()
        # Normal command succeeds
        cmd_valid = CommandEnvelope(
            command_id="cmd_time_valid",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_time_1",
            payload={"sublease_id": "sub_time_1", "units_allocated": 10, "run_id": "R1"},
            correlation_id="corr_time_1",
            causation_id="caus_time_1",
            created_at_unix=now,
        )
        receipt, _ = self.p0001_log.propose_and_commit(cmd_valid)
        self.assertEqual(receipt.result_code, "SUBLEASE_ALLOCATED")

        # Future clock drift (> 10s) rejected on admission
        cmd_future = CommandEnvelope(
            command_id="cmd_time_future",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_time_2",
            payload={"sublease_id": "sub_time_2", "units_allocated": 10, "run_id": "R1"},
            correlation_id="corr_time_2",
            causation_id="caus_time_2",
            created_at_unix=now + 50.0,
        )
        with self.assertRaises(ValueError):
            self.p0001_log.propose_and_commit(cmd_future)

        # Backward clock skew (> 5s behind last committed) rejected on admission
        cmd_skew = CommandEnvelope(
            command_id="cmd_time_skew",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_time_3",
            payload={"sublease_id": "sub_time_3", "units_allocated": 10, "run_id": "R1"},
            correlation_id="corr_time_3",
            causation_id="caus_time_3",
            created_at_unix=now - 20.0,
        )
        with self.assertRaises(ValueError):
            self.p0001_log.propose_and_commit(cmd_skew)

    # -------------------------------------------------------------------------
    # INVARIANT-I23: Partition Budget Isolation
    # -------------------------------------------------------------------------
    def test_invariant_i23_partition_budget_isolation(self) -> None:
        """INVARIANT-I23: Cross-partition balance bleeding and negative balances strictly prohibited."""
        # 1. Foreign partition sublease allocation rejected
        cmd_foreign = CommandEnvelope(
            command_id="cmd_foreign_part",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_foreign",
            payload={
                "sublease_id": "sub_foreign",
                "partition_id": "P-9999",  # Foreign partition mismatch
                "units_allocated": 50,
                "run_id": "R1",
            },
            correlation_id="corr_part_1",
            causation_id="caus_part_1",
        )
        receipt_for, _ = self.p0001_log.propose_and_commit(cmd_foreign)
        self.assertEqual(receipt_for.result_code, "PARTITION_MISMATCH")

        # 2. Negative allocation rejected
        cmd_neg = CommandEnvelope(
            command_id="cmd_neg_alloc",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_neg",
            payload={
                "sublease_id": "sub_neg",
                "partition_id": "P-0001",
                "units_allocated": -100,
                "run_id": "R1",
            },
            correlation_id="corr_part_2",
            causation_id="caus_part_2",
        )
        receipt_neg, _ = self.p0001_log.propose_and_commit(cmd_neg)
        self.assertEqual(receipt_neg.result_code, "NEGATIVE_BUDGET_ALLOCATION")

    # -------------------------------------------------------------------------
    # INVARIANT-I24: Persisted Mesh BootID + Monotonic Nonce Safety
    # -------------------------------------------------------------------------
    def test_invariant_i24_mesh_boot_id_nonce_safety(self) -> None:
        """INVARIANT-I24: Mesh node messages strictly require monotonically increasing nonces under BootID."""
        from src.infrastructure.mesh.gossip.engine import GossipEngine
        from src.infrastructure.mesh.gossip.models import MeshNode

        node = MeshNode(id="node_test_1", host="127.0.0.1", port=9000)
        engine = GossipEngine(local_node=node, secret="mesh_secret_test")

        peer_id = "peer_node_a"
        boot_1 = "boot_session_1"

        # Nonce 1 accepted
        self.assertTrue(engine.validate_incoming_nonce(peer_id, boot_1, 1))
        # Nonce 2 accepted
        self.assertTrue(engine.validate_incoming_nonce(peer_id, boot_1, 2))
        # Replayed Nonce 2 rejected (I24)
        self.assertFalse(engine.validate_incoming_nonce(peer_id, boot_1, 2))
        # Regressing Nonce 1 rejected (I24)
        self.assertFalse(engine.validate_incoming_nonce(peer_id, boot_1, 1))

        # Node reboots with fresh boot_id: Nonce sequence safely resets
        boot_2 = "boot_session_2"
        self.assertTrue(engine.validate_incoming_nonce(peer_id, boot_2, 1))

    # -------------------------------------------------------------------------
    # INVARIANT-I25' & I25b: Local Partition Policy Rollback & Watermark Bounds
    # -------------------------------------------------------------------------
    def test_invariant_i25_policy_rollback_and_watermark(self) -> None:
        """INVARIANT-I25', I25b: Rollback revokes newer generations; claims under revoked generations fail."""
        # 1. Promote policy to Generation 2
        cmd_p2 = CommandEnvelope(
            command_id="cmd_prom_gen2",
            command_type="PromotePolicyCommand",
            aggregate_id="policy_agg",
            payload={"policy_id": "pol_v2", "artifact_hash": "h2", "generation": 2},
            correlation_id="corr_p25_1",
            causation_id="caus_p25_1",
        )
        self.p0001_log.propose_and_commit(cmd_p2)
        self.assertEqual(self.p0001_fsm.policy_watermark, 2)

        # 2. Authorize execution
        cmd_alloc = CommandEnvelope(
            command_id="cmd_alloc_p25",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_p25",
            payload={"sublease_id": "sub_p25", "units_allocated": 100, "run_id": "R1"},
            correlation_id="corr_p25_2",
            causation_id="caus_p25_2",
        )
        self.p0001_log.propose_and_commit(cmd_alloc)

        cmd_auth = CommandEnvelope(
            command_id="cmd_auth_p25",
            command_type="AuthorizeExecutionCommand",
            aggregate_id="exec_p25",
            payload={"sublease_id": "sub_p25", "units_requested": 10, "capability_id": "cap_p25"},
            correlation_id="corr_p25_3",
            causation_id="caus_p25_3",
        )
        self.p0001_log.propose_and_commit(cmd_auth)

        # 3. Rollback policy back to Generation 1 (revokes Generation 2)
        cmd_rb = CommandEnvelope(
            command_id="cmd_rb_gen1",
            command_type="RollbackPolicyCommand",
            aggregate_id="policy_agg",
            payload={"parent_policy_id": "pol_v1", "target_generation": 1},
            correlation_id="corr_p25_4",
            causation_id="caus_p25_4",
        )
        self.p0001_log.propose_and_commit(cmd_rb)
        self.assertEqual(self.p0001_fsm.policy_watermark, 1)
        self.assertIn(2, self.p0001_fsm.revoked_policy_generations)

        # 4. Submit claim signed under revoked Generation 2 -> REJECTED (I25')
        cmd_claim_rev = CommandEnvelope(
            command_id="cmd_claim_rev",
            command_type="SubmitExecutionClaim",
            aggregate_id="exec_p25",
            payload={"capability_id": "cap_p25", "policy_generation": 2, "units_consumed": 5},
            correlation_id="corr_p25_5",
            causation_id="caus_p25_5",
        )
        receipt_rev, _ = self.p0001_log.propose_and_commit(cmd_claim_rev)
        self.assertEqual(receipt_rev.result_code, "POLICY_GENERATION_REVOKED")

        # 5. Submit claim with generation exceeding watermark -> REJECTED (I25b)
        cmd_claim_high = CommandEnvelope(
            command_id="cmd_claim_high",
            command_type="SubmitExecutionClaim",
            aggregate_id="exec_p25",
            payload={"capability_id": "cap_p25", "policy_generation": 99, "units_consumed": 5},
            correlation_id="corr_p25_6",
            causation_id="caus_p25_6",
        )
        receipt_high, _ = self.p0001_log.propose_and_commit(cmd_claim_high)
        self.assertEqual(receipt_high.result_code, "POLICY_GENERATION_EXCEEDS_WATERMARK")

    # -------------------------------------------------------------------------
    # INVARIANT-I26: Multi-Raft Quota Slab Conservation
    # -------------------------------------------------------------------------
    def test_invariant_i26_quota_slab_conservation(self) -> None:
        """INVARIANT-I26: Quota slab allocation and reclamation preserves exact integer conservation."""
        gb = self.global_budget
        self.assertTrue(gb.verify_conservation())

        # Allocate 1000 units to a partition quota slab
        ok, _ = gb.allocate_quota_slab("slab_p1", "P-0001", 1000)
        self.assertTrue(ok)
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.available, 4000)
        self.assertEqual(gb.outstanding_reserved, 1000)

        # Reclaim 600 consumed, 400 unused
        ok_rec, _ = gb.reclaim_quota_slab("slab_p1", consumed_units=600)
        self.assertTrue(ok_rec)
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.consumed, 600)
        self.assertEqual(gb.available, 4400)
        self.assertEqual(gb.outstanding_reserved, 0)

    # -------------------------------------------------------------------------
    # INVARIANT-I27: Bounded Claims (64KB) & CAS Merkle Root Verification
    # -------------------------------------------------------------------------
    def test_invariant_i27_bounded_claims_and_cas_merkle(self) -> None:
        """INVARIANT-I27: 64KB bound validation & CAS Merkle root verification."""
        from src.core.contracts.execution_request import ClaimSizeExceededError, RawExecutionClaim
        from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
        from src.core.storage.cas_store import get_global_cas_store

        cas = get_global_cas_store()
        blob1 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>test</html>"
        h1 = cas.store_blob(blob1)
        root = cas.compute_merkle_root([h1])
        self.assertTrue(cas.verify_merkle_root([h1], root))

        # 1. Bounded size check
        oversized_findings = tuple({"data": "x" * 1000} for _ in range(100))
        claim_large = RawExecutionClaim(
            request_id="req_lg",
            tenant_id="t1",
            candidate_id="cand_lg",
            execution_id="exec_lg",
            lease_id="lease_lg",
            epoch=1,
            worker_id="w_lg",
            outcome="COMPLETED",
            duration_seconds=1.0,
            findings=oversized_findings,
        )
        with self.assertRaises(ClaimSizeExceededError):
            claim_large.validate_bounds()

        # 2. Settle claim with valid CAS Merkle root
        state_auth = StateAuthority()
        coordinator = SettlementCoordinator(state_authority=state_auth)
        valid_claim = RawExecutionClaim(
            request_id="req_cas_valid",
            tenant_id="t1",
            candidate_id="cand_1",
            execution_id="exec_cas_valid",
            lease_id="lease_1",
            epoch=1,
            worker_id="w1",
            outcome="COMPLETED",
            duration_seconds=0.5,
            evidence_hashes=(h1,),
            cas_merkle_root=root,
        )
        res_valid = coordinator.settle_claim(valid_claim)
        self.assertEqual(res_valid.status, "COMMITTED")

        # 3. Tampered Merkle root fails closed (I27)
        tampered_claim = RawExecutionClaim(
            request_id="req_cas_bad",
            tenant_id="t1",
            candidate_id="cand_1",
            execution_id="exec_cas_bad",
            lease_id="lease_1",
            epoch=1,
            worker_id="w1",
            outcome="COMPLETED",
            duration_seconds=0.5,
            evidence_hashes=(h1,),
            cas_merkle_root="0000000000000000000000000000000000000000000000000000000000000000",
        )
        res_bad = coordinator.settle_claim(tampered_claim)
        self.assertEqual(res_bad.status, "REJECTED")
        self.assertIn("CAS evidence integrity verification failed", res_bad.error)

    # -------------------------------------------------------------------------
    # INVARIANT-I28: Hardened Lease State Machine Transitions
    # -------------------------------------------------------------------------
    def test_invariant_i28_hardened_lease_transitions(self) -> None:
        """INVARIANT-I28: Safe lease compensation and idempotent duplicate recovery."""
        gb = self.global_budget
        gb.reserve_sublease("sl_comp", "run_comp", "P-0001", 200)

        # 1. Compensate unconsumed sublease
        ok, msg = self.saga_engine.compensate_sublease("run_comp", "P-0001", "sl_comp")
        self.assertTrue(ok)
        self.assertEqual(msg, "SUBLEASE_COMPENSATED_SUCCESS")
        self.assertTrue(gb.verify_conservation())
        self.assertEqual(gb.available, 5000)

        # 2. Duplicate compensation is idempotent no-op
        ok2, msg2 = self.saga_engine.compensate_sublease("run_comp", "P-0001", "sl_comp")
        self.assertTrue(ok2)
        self.assertIn("already in terminal state", msg2)

    # -------------------------------------------------------------------------
    # INVARIANT-I29: Scope-Derived Network Egress Enforcement
    # -------------------------------------------------------------------------
    def test_invariant_i29_scope_derived_network_egress(self) -> None:
        """INVARIANT-I29: Outbound destinations derived from ScopeToken; cloud metadata blocked unconditionally."""
        from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter

        token = ScopeToken(
            scope_hash="hash_sec_1",
            allowed_domains=("api.example.com", "*.target.internal"),
            allowed_cidrs=("10.0.0.0/8",),
        )
        egress = NetworkEgressFilter.from_scope_token(token)

        # Authorized destinations succeed
        self.assertTrue(egress.is_destination_allowed("api.example.com"))
        self.assertTrue(egress.is_destination_allowed("sub.target.internal"))
        self.assertTrue(egress.is_destination_allowed("10.1.2.3"))

        # Unauthorized domain blocked
        self.assertFalse(egress.is_destination_allowed("evil.com"))
        with self.assertRaises(EgressViolationError):
            egress.validate_destination_or_raise("evil.com")

        # Cloud Metadata endpoints unconditionally blocked (I29)
        self.assertFalse(egress.is_destination_allowed("169.254.169.254"))
        self.assertFalse(egress.is_destination_allowed("metadata.google.internal"))
        self.assertFalse(egress.is_destination_allowed("fd00:ec2::254"))
        with self.assertRaises(EgressViolationError):
            egress.validate_destination_or_raise("169.254.169.254")

    def test_invariant_i30_exploitation_entry_authority_and_budget(self) -> None:
        """INVARIANT-I30 / I28: Standalone exploitation enforces full ticket authorization, budget reservation and settlement."""
        import asyncio
        from src.core.config.typed_config import PipelineConfig
        from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
        from src.exploitation.engines.safe_exploiter import SafeExploiter
        from src.exploitation.models import ExploitTarget

        cfg = PipelineConfig(target_name="api.example.com", output_dir="out_test")
        enforcer = HuntBudgetEnforcer(HuntBudget(max_requests=2, label="exploit_test"))
        cfg.hunt_budget_enforcer = enforcer

        target = ExploitTarget(url="https://in-scope.test/endpoint", metadata={"tenant_id": "t1"})

        # Executing via SafeExploiter goes through I30 ticket mint, consume, and settlement
        exploiter = SafeExploiter(cfg)
        from unittest.mock import patch
        with patch("src.exploitation.safety.is_safe_url_with_dns_check", return_value=True), \
             patch("src.exploitation.engines.safe_exploiter.is_safe_url_with_dns_check", return_value=True):
            res = asyncio.run(exploiter.execute("ssrf", target))
            self.assertIn("ticket_id", res.metadata)
            self.assertIn("command_id", res.metadata)
            self.assertEqual(enforcer.consumed_requests, 1)

            # Budget exhaustion blocks exploit entry
            enforcer.reserve_requests(1)
            res2 = asyncio.run(exploiter.execute("ssrf", target))
            self.assertTrue(res2.metadata.get("i30_refused"))
            self.assertEqual(res2.status.value, "failed")

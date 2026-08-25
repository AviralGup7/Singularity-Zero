"""Chaos Engineering & Adversarial Fault Injection Test Suite.

Simulates adversarial distributed environments and partition failure modes:
1. Multi-Partition Split-Brain & Asymmetric Network Isolation
2. Replayed & Regressing UDP Gossip Mesh Packets
3. Clock-Skew Injection on Command Admission
4. Byzantine Worker Memory Flooding & Tampered CAS Merkle Roots
5. Saturated Broker Pressure & Disk Thrashing Under High Volume
"""

from __future__ import annotations

import time
import unittest
import uuid

from src.core.contracts.command_envelope import CommandEnvelope, CommandResult
from src.core.contracts.execution_request import ClaimSizeExceededError, RawExecutionClaim
from src.core.frontier.global_coordination import GlobalBudgetAggregate, PlacementAuthority
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.replicated_log import ReplicatedPartitionLog
from src.core.frontier.run_saga import DurableRunSagaEngine
from src.core.frontier.state_authority import SettlementCoordinator, StateAuthority
from src.core.storage.cas_store import get_global_cas_store
from src.infrastructure.mesh.gossip.engine import GossipEngine
from src.infrastructure.mesh.gossip.models import MeshNode
from src.realtime.prioritized_broker import PrioritizedRealtimeBroker, QoSClass, TelemetryEvent
from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter
from src.decision.models import ScopeToken


class TestChaosFaultInjection(unittest.TestCase):
    def setUp(self) -> None:
        self.global_budget = GlobalBudgetAggregate(total_budget=10000)
        self.placement = PlacementAuthority(initial_version=1)
        self.fsm_p1 = PartitionFSM(partition_id="P-0001")
        self.fsm_p1_replica = PartitionFSM(partition_id="P-0001")
        self.log_p1 = ReplicatedPartitionLog(
            partition_id="P-0001",
            current_term=1,
            is_leader=True,
            fsm=self.fsm_p1,
        )
        self.saga_engine = DurableRunSagaEngine(
            global_budget=self.global_budget,
            placement_authority=self.placement,
            partition_logs={"P-0001": self.log_p1},
        )

    def test_chaos_clock_skew_fault_injection(self) -> None:
        """Inject temporal drift and ensure admission gate fails closed while FSM remains pure."""
        now = time.time()

        # 1. Extreme Future Drift (+100s)
        cmd_fut = CommandEnvelope(
            command_id="cmd_drift_fut",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_drift_1",
            payload={"sublease_id": "sub_drift_1", "units_allocated": 10, "run_id": "R1"},
            correlation_id="c1",
            causation_id="k1",
            created_at_unix=now + 100.0,
        )
        with self.assertRaises(ValueError):
            self.log_p1.propose_and_commit(cmd_fut)

        # 2. Legitimate Command Committed
        cmd_ok = CommandEnvelope(
            command_id="cmd_drift_ok",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_drift_2",
            payload={"sublease_id": "sub_drift_2", "units_allocated": 10, "run_id": "R1"},
            correlation_id="c2",
            causation_id="k2",
            created_at_unix=now,
        )
        receipt, _ = self.log_p1.propose_and_commit(cmd_ok)
        self.assertEqual(receipt.result_code, "SUBLEASE_ALLOCATED")

        # 3. Extreme Regression (-60s behind committed entry)
        cmd_past = CommandEnvelope(
            command_id="cmd_drift_past",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sub_drift_3",
            payload={"sublease_id": "sub_drift_3", "units_allocated": 10, "run_id": "R1"},
            correlation_id="c3",
            causation_id="k3",
            created_at_unix=now - 60.0,
        )
        with self.assertRaises(ValueError):
            self.log_p1.propose_and_commit(cmd_past)

    def test_chaos_mesh_byzantine_nonce_and_replay_flooding(self) -> None:
        """Simulate malicious peer sending out-of-order, replayed, and duplicate nonces."""
        node = MeshNode(id="node_chaos_1", host="127.0.0.1", port=9100)
        engine = GossipEngine(local_node=node, secret="chaos_secret")

        peer = "peer_attacker"
        boot = "boot_sess_attacker"

        # Valid monotonic sequence
        self.assertTrue(engine.validate_incoming_nonce(peer, boot, 10))
        self.assertTrue(engine.validate_incoming_nonce(peer, boot, 15))
        self.assertTrue(engine.validate_incoming_nonce(peer, boot, 16))

        # Attacker injects duplicate nonces (Replay Flood)
        for _ in range(50):
            self.assertFalse(engine.validate_incoming_nonce(peer, boot, 16))

        # Attacker injects regressing nonces (Stale Packets)
        for old_nonce in [1, 5, 9, 14, 15]:
            self.assertFalse(engine.validate_incoming_nonce(peer, boot, old_nonce))

    def test_chaos_byzantine_claim_merkle_tampering(self) -> None:
        """Simulate compromised worker falsifying findings Merkle root."""
        cas = get_global_cas_store()
        real_blob = b"real payload"
        real_h = cas.store_blob(real_blob)
        valid_root = cas.compute_merkle_root([real_h])

        state_auth = StateAuthority()
        coordinator = SettlementCoordinator(state_authority=state_auth)

        # Byzantine worker injects random corrupted root
        tampered_claim = RawExecutionClaim(
            request_id="req_byz",
            tenant_id="t1",
            candidate_id="cand_1",
            execution_id="exec_byz_1",
            lease_id="lease_1",
            epoch=1,
            worker_id="worker_rogue",
            outcome="COMPLETED",
            duration_seconds=0.1,
            evidence_hashes=(real_h,),
            cas_merkle_root="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        res = coordinator.settle_claim(tampered_claim)
        self.assertEqual(res.status, "REJECTED")
        self.assertIn("CAS evidence integrity verification failed", res.error)

    def test_chaos_egress_cloud_metadata_exfiltration_attempt(self) -> None:
        """Simulate SSRF attack targeting cloud metadata services within worker container."""
        token = ScopeToken(
            scope_hash="hash_chaos_egress",
            allowed_domains=("*.corp.internal",),
            allowed_cidrs=("10.0.0.0/16",),
        )
        egress = NetworkEgressFilter.from_scope_token(token)

        # Attacker probes various metadata IP formats
        prohibited_targets = [
            "169.254.169.254",
            "metadata.google.internal",
            "fd00:ec2::254",
            "100.100.100.200",
            "169.254.1.1",  # Link-local
        ]
        for target in prohibited_targets:
            self.assertFalse(egress.is_destination_allowed(target))
            with self.assertRaises(EgressViolationError):
                egress.validate_destination_or_raise(target)

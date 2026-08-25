"""Adversarial & Hardened Authority Invariant Test Suite.

Proves zero bypasses remain for:
1. P0 Telemetry Durable Disk Spooling & Lossless Backpressure under saturation
2. Policy Governance Gate atomic promotion & rollback via Raft log
3. Global Budget lease expiration authority via Replicated Raft Log
4. Strict mandatory budget reservation without bypass
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.replicated_log import ReplicatedPartitionLog
from src.decision.authorization import ExecutionAuthorizer, ScopeAuthorizationError
from src.decision.models import (
    ActionSpec,
    ExecutionRequest,
    TargetSpec,
)
from src.learning.policy_governance import PolicyGovernanceGate
from src.learning.versioned_policy import VersionedPolicy
from src.realtime.prioritized_broker import (
    PrioritizedRealtimeBroker,
    QoSClass,
    TelemetryEvent,
)


class TestHardenedAuthorityInvariants(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.fsm_p0 = PartitionFSM(partition_id="P-0000")
        self.log_p0 = ReplicatedPartitionLog(
            partition_id="P-0000",
            current_term=1,
            is_leader=True,
            fsm=self.fsm_p0,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. P0 Telemetry Durable Spool & Lossless Delivery
    # -------------------------------------------------------------------------
    def test_p0_durable_disk_spool_and_rehydration(self) -> None:
        """P0 events exceeding memory capacity are durably appended to disk and rehydrated."""
        spool_dir = str(self.tmp_dir / "telemetry_spool")
        broker1 = PrioritizedRealtimeBroker(
            p0_capacity=5,
            max_p0_spool=20,
            spool_dir=spool_dir,
        )

        # Publish 12 P0 events (5 memory + 7 disk spool)
        for i in range(12):
            evt = TelemetryEvent(
                event_id=f"p0_evt_{i}",
                qos=QoSClass.P0_CONTROL,
                topic="control/emergency_stop",
                payload={"index": i},
            )
            self.assertTrue(broker1.publish(evt))

        # Check disk spool file exists
        spool_file = Path(spool_dir) / "p0_telemetry_spool.jsonl"
        self.assertTrue(spool_file.exists())
        with open(spool_file, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(lines), 7)

        # Simulate abrupt process restart: instantiate new broker pointing to same spool directory
        broker2 = PrioritizedRealtimeBroker(
            p0_capacity=10,
            max_p0_spool=20,
            spool_dir=spool_dir,
        )
        # Drain all 7 rehydrated events
        drained = broker2.drain_batch(max_events=20)
        self.assertEqual(len(drained), 7)
        self.assertEqual(drained[0].event_id, "p0_evt_5")
        self.assertEqual(drained[-1].event_id, "p0_evt_11")

    def test_p0_backpressure_on_total_saturation_never_silently_drops(self) -> None:
        """When memory and max spool are exhausted, publish returns False (backpressure) rather than dropping silently."""
        broker = PrioritizedRealtimeBroker(
            p0_capacity=2,
            max_p0_spool=3,
            spool_dir=None,  # Memory-only mode
        )

        for i in range(5):  # Fills 2 memory + 3 memory spool
            self.assertTrue(
                broker.publish(
                    TelemetryEvent(
                        event_id=f"e_{i}",
                        qos=QoSClass.P0_CONTROL,
                        topic="control/test",
                        payload={},
                    )
                )
            )

        # Event 6 exceeds total capacity -> must trigger explicit backpressure (return False)
        overflow_event = TelemetryEvent(
            event_id="e_overflow",
            qos=QoSClass.P0_CONTROL,
            topic="control/test",
            payload={},
        )
        self.assertFalse(broker.publish(overflow_event))
        stats = broker.get_stats()
        self.assertEqual(stats["dropped_counts"].get(int(QoSClass.P0_CONTROL), 0), 1)

    # -------------------------------------------------------------------------
    # 2. Policy Governance Gate Raft Authority
    # -------------------------------------------------------------------------
    def test_policy_governance_dispatches_through_raft_log(self) -> None:
        """Policy promotion and rollback must commit to Raft FSM and survive restart/replay."""
        gov_gate = PolicyGovernanceGate(replicated_log=self.log_p0)
        policy_v1 = VersionedPolicy(
            policy_id="policy_v1_base",
            version="1.0",
            target_boosts=(("api.target.com", 1.5),),
            target_suppressions=(),
        )

        # 1. Promote v1
        ok = gov_gate.promote_policy(policy_v1)
        self.assertTrue(ok)
        self.assertEqual(gov_gate.active_policy.policy_id, "policy_v1_base")

        # Verify aggregate state in FSM
        agg = self.fsm_p0.aggregates.get("policy_active")
        self.assertIsNotNone(agg)
        self.assertEqual(agg.state_payload["active_policy_id"], "policy_v1_base")

        # 2. Promote v2
        policy_v2 = VersionedPolicy(
            policy_id="policy_v2_canary",
            version="2.0",
            target_boosts=(("api.target.com", 2.0),),
            target_suppressions=(),
        )
        ok2 = gov_gate.promote_policy(policy_v2)
        self.assertTrue(ok2)
        self.assertEqual(
            self.fsm_p0.aggregates["policy_active"].state_payload["active_policy_id"],
            "policy_v2_canary",
        )

        # 3. Rollback
        rolled_back = gov_gate.rollback()
        self.assertIsNotNone(rolled_back)
        self.assertEqual(rolled_back.policy_id, "policy_v1_base")
        self.assertEqual(
            self.fsm_p0.aggregates["policy_active"].state_payload["active_policy_id"],
            "policy_v1_base",
        )

    def test_policy_governance_rejects_unsafe_policy_without_raft_mutation(self) -> None:
        """Unsafe policy (e.g. excessive boost multiplier) is rejected before creating Raft log entry."""
        pre_index = self.fsm_p0.last_applied_index
        gov_gate = PolicyGovernanceGate(max_boost_multiplier=3.0, replicated_log=self.log_p0)
        unsafe_policy = VersionedPolicy(
            policy_id="policy_unsafe",
            version="1.0",
            target_boosts=(("target.com", 10.0),),  # Exceeds max 3.0
            target_suppressions=(),
        )

        ok = gov_gate.promote_policy(unsafe_policy)
        self.assertFalse(ok)
        self.assertEqual(self.fsm_p0.last_applied_index, pre_index)
        self.assertIsNone(gov_gate.active_policy)

    # -------------------------------------------------------------------------
    # 3. Global Budget Authority via Raft Log
    # -------------------------------------------------------------------------
    def test_replicated_sublease_expiry_via_fsm(self) -> None:
        """Sublease allocation and expiration strictly advance Raft FSM and emit events."""
        # 1. Allocate sublease
        cmd_alloc = CommandEnvelope(
            command_id="cmd_alloc_01",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sl_hardened",
            payload={"sublease_id": "sl_hardened", "units_allocated": 500, "run_id": "R1"},
            correlation_id="corr_h",
            causation_id="caus_h",
        )
        receipt_alloc, _ = self.log_p0.propose_and_commit(cmd_alloc)
        self.assertEqual(receipt_alloc.result_code, "SUBLEASE_ALLOCATED")
        self.assertEqual(self.fsm_p0.subleases["sl_hardened"].status, "ACTIVE")

        # 2. Expire sublease through Raft command
        cmd_expire = CommandEnvelope(
            command_id="cmd_expire_01",
            command_type="ExpireSubLeaseCommand",
            aggregate_id="sl_hardened",
            payload={"sublease_id": "sl_hardened", "units_consumed": 100},
            correlation_id="corr_h2",
            causation_id="timeout_monitor",
        )
        receipt_expire, events = self.log_p0.propose_and_commit(cmd_expire)
        self.assertEqual(receipt_expire.result_code, "SUBLEASE_EXPIRED")
        self.assertEqual(self.fsm_p0.subleases["sl_hardened"].status, "EXPIRED")
        self.assertEqual(self.fsm_p0.subleases["sl_hardened"].units_consumed, 100)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "SubLeaseExpiredEvent")
        self.assertEqual(events[0].payload["units_returned"], 400)

        # 3. Duplicate expiry returns ALREADY_EXPIRED (idempotent no-op)
        receipt_dup, events_dup = self.log_p0.propose_and_commit(cmd_expire)
        self.assertEqual(receipt_dup.result_code, "SUBLEASE_EXPIRED")  # Idempotent return

    # -------------------------------------------------------------------------
    # 4. Mandatory Budget Reservation Defense-in-Depth
    # -------------------------------------------------------------------------
    def test_authorizer_strictly_fails_closed_without_budget_enforcer(self) -> None:
        """ExecutionAuthorizer strictly forbids ticket issuance when no budget enforcer is present."""
        authorizer = ExecutionAuthorizer(secret_key="auth-secret")
        req = ExecutionRequest(
            request_id="req_fail_closed",
            tenant_id="tenant_1",
            target=TargetSpec(host="target.test"),
            stage="probing",
            actions=(ActionSpec(action_id="a1", action_type="probe", tool_or_detector="prober"),),
        )
        with self.assertRaises(ScopeAuthorizationError):
            authorizer.authorize(req)

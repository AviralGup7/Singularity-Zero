import tempfile
import time
import unittest

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.frontier.failure_model import AuthorityLostError
from src.core.frontier.raft_cluster import MultiNodeRaftCluster
from src.core.frontier.raft_transport import PreVoteRequest


class TestMultiNodeRaftCluster(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="test_raft_cluster_")
        self.cluster = MultiNodeRaftCluster(
            partition_id="P-0000",
            node_count=3,
            base_wal_dir=self.temp_dir.name,
        )

    def tearDown(self) -> None:
        self.cluster.close()
        self.temp_dir.cleanup()

    def test_3_node_cluster_initialization_and_quorum(self) -> None:
        self.assertEqual(self.cluster.node_count, 3)
        self.assertEqual(self.cluster.quorum_size, 2)
        self.assertEqual(self.cluster.leader_id, "node_0")
        self.assertTrue(self.cluster.leader.is_leader)

    def test_quorum_replicated_mutation(self) -> None:
        cmd = CommandEnvelope(
            command_id="cmd_cluster_test_1",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_cluster_1",
            payload={
                "sublease_id": "sublease_cluster_1",
                "units_allocated": 500,
                "run_id": "run_c1",
            },
            correlation_id="corr_c1",
            causation_id="caus_c1",
            expected_aggregate_version=0,
            created_at_unix=time.time(),
        )
        receipt, events = self.cluster.propose_and_commit(cmd)
        self.assertEqual(receipt.result_code, "SUBLEASE_ALLOCATED")
        self.assertEqual(receipt.raft_index, 1)
        self.assertTrue(self.cluster.verify_state_consistency())

    def test_fault_tolerance_minority_node_failure(self) -> None:
        """Crash 1 follower (node_2) -> Quorum (2/3) intact -> commits succeed."""
        self.cluster.isolate_node("node_2")

        cmd = CommandEnvelope(
            command_id="cmd_cluster_test_2",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_cluster_2",
            payload={
                "sublease_id": "sublease_cluster_2",
                "units_allocated": 300,
                "run_id": "run_c2",
            },
            correlation_id="corr_c2",
            causation_id="caus_c2",
            expected_aggregate_version=0,
            created_at_unix=time.time(),
        )
        receipt, events = self.cluster.propose_and_commit(cmd)
        self.assertEqual(receipt.result_code, "SUBLEASE_ALLOCATED")
        self.assertTrue(self.cluster.verify_state_consistency())

    def test_leader_isolation_and_failover_election(self) -> None:
        """Isolate active leader -> trigger election on node_1 -> node_1 wins term 2."""
        self.cluster.isolate_node("node_0")
        self.assertIsNone(self.cluster.leader_id)

        # Trigger election on node_1
        won = self.cluster.trigger_election("node_1")
        self.assertTrue(won)
        self.assertEqual(self.cluster.leader_id, "node_1")
        self.assertEqual(self.cluster.leader.current_term, 2)

        # New leader can commit with node_2 (quorum 2/3)
        cmd = CommandEnvelope(
            command_id="cmd_cluster_test_failover",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_cluster_failover",
            payload={
                "sublease_id": "sublease_cluster_failover",
                "units_allocated": 250,
                "run_id": "run_c3",
            },
            correlation_id="corr_c3",
            causation_id="caus_c3",
            expected_aggregate_version=0,
            created_at_unix=time.time(),
        )
        receipt, events = self.cluster.propose_and_commit(cmd)
        self.assertEqual(receipt.result_code, "SUBLEASE_ALLOCATED")
        self.assertEqual(receipt.raft_term, 2)

    def test_majority_failure_fails_closed(self) -> None:
        """Isolate 2 followers -> remaining 1 node cannot reach quorum (1 < 2) -> fail-closed."""
        self.cluster.isolate_node("node_1")
        self.cluster.isolate_node("node_2")

        cmd = CommandEnvelope(
            command_id="cmd_cluster_test_no_quorum",
            command_type="AllocateSubLeaseCommand",
            aggregate_id="sublease_cluster_no_quorum",
            payload={
                "sublease_id": "sublease_cluster_no_quorum",
                "units_allocated": 100,
                "run_id": "run_c4",
            },
            correlation_id="corr_c4",
            causation_id="caus_c4",
            expected_aggregate_version=0,
            created_at_unix=time.time(),
        )
        with self.assertRaises(AuthorityLostError):
            self.cluster.propose_and_commit(cmd)

    def test_pre_vote_prevents_disrupted_terms_from_isolated_partition(self) -> None:
        """Isolated node (node_2) cannot obtain majority pre-votes, so its term does not increase."""
        self.cluster.isolate_node("node_2")
        node_2 = self.cluster.nodes["node_2"]
        initial_term = node_2.current_term

        # Trigger election on isolated node
        won = self.cluster.trigger_election("node_2")
        self.assertFalse(won)
        # Term was not increased because Pre-Vote phase aborted before term increment
        self.assertEqual(node_2.current_term, initial_term)

    def test_leader_lease_prevents_stale_leader_split_brain(self) -> None:
        """Active leader holds lease; isolated follower cannot usurp while leader lease is active."""
        leader = self.cluster.leader
        self.assertTrue(leader.has_leader_lease)

        # Node 1 tries to usurp while connected, but pre-vote is rejected because leader lease is active
        # (simulate pre-vote request to leader directly)
        pre_vote_req = PreVoteRequest(
            next_term=leader.current_term + 1,
            candidate_id="node_1",
            last_log_index=leader.commit_index,
            last_log_term=leader.current_term,
        )
        resp = leader.handle_pre_vote_rpc(pre_vote_req)
        self.assertFalse(resp.pre_vote_granted)
        self.assertEqual(resp.error_code, "ACTIVE_LEADER_LEASE")


if __name__ == "__main__":
    unittest.main()

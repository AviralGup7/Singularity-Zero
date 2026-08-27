import unittest
from dataclasses import dataclass
from unittest.mock import MagicMock
from src.infrastructure.mesh.consensus import MeshConsensus


@dataclass
class MockPeerStat:
    round_trip_time: float


class TestMeshConsensusCrossRegion(unittest.TestCase):
    def test_local_default_election_timeout(self) -> None:
        gossip = MagicMock()
        gossip.peer_stats = {}
        consensus = MeshConsensus(gossip, region="local", election_timeout_sec=10.0)
        self.assertEqual(consensus.election_timeout_sec, 10.0)

    def test_cross_region_base_scaling(self) -> None:
        gossip = MagicMock()
        gossip.peer_stats = {}
        consensus = MeshConsensus(gossip, region="cross-region", election_timeout_sec=10.0)
        # Should scale up from 10.0 to 30.0s floor for cross-region
        self.assertEqual(consensus.election_timeout_sec, 30.0)

    def test_rtt_scaled_adaptive_election_timeout(self) -> None:
        gossip = MagicMock()
        # Simulated WAN RTTs of 200ms, 250ms, 300ms (median 250ms = 0.25s)
        gossip.peer_stats = {
            "peer_1": MockPeerStat(round_trip_time=0.20),
            "peer_2": MockPeerStat(round_trip_time=0.25),
            "peer_3": MockPeerStat(round_trip_time=0.30),
        }
        consensus = MeshConsensus(
            gossip,
            region="local",
            election_timeout_sec=1.0,
            rtt_multiplier=10.0,
        )
        # 10x median RTT = 10 * 0.25s = 2.5s
        self.assertEqual(consensus.election_timeout_sec, 2.5)

    def test_prevote_prevents_isolated_node_takeover(self) -> None:
        gossip = MagicMock()
        # 3-node cluster: local node + 2 dead peers
        peer_1 = MagicMock(status="dead")
        peer_2 = MagicMock(status="dead")
        gossip.peers = {"peer_1": peer_1, "peer_2": peer_2}

        consensus = MeshConsensus(gossip)
        # Total nodes = 3, quorum = 2. Local node has 0 alive peers -> total reachable = 1 < 2 -> fails pre-vote
        self.assertFalse(consensus._passes_prevote_check())

    def test_prevote_allows_quorum_connected_node_takeover(self) -> None:
        gossip = MagicMock()
        # 3-node cluster: local node + 1 alive peer + 1 dead peer
        peer_1 = MagicMock(status="alive")
        peer_2 = MagicMock(status="dead")
        gossip.peers = {"peer_1": peer_1, "peer_2": peer_2}

        consensus = MeshConsensus(gossip)
        # Total nodes = 3, quorum = 2. Local node has 1 alive peer -> total reachable = 2 >= 2 -> passes pre-vote
        self.assertTrue(consensus._passes_prevote_check())


if __name__ == "__main__":
    unittest.main()

import unittest
from src.core.frontier.state import NeuralState


class TestAdaptiveTombstoneTTL(unittest.TestCase):
    def test_adaptive_tombstone_ttl_scales_with_gossip_rtt(self) -> None:
        state = NeuralState()

        # Baseline default TTL (3600.0 seconds)
        ttl_default = state.compute_adaptive_tombstone_ttl()
        self.assertEqual(ttl_default, 3600.0)

        # Under degraded network / high gossip RTT (e.g. partition with 2000s RTT)
        state.update_observed_gossip_rtt(observed_rtt_sec=2000.0)
        # Safety factor = 3.0 -> adaptive TTL = 6000.0s
        ttl_adapted = state.compute_adaptive_tombstone_ttl()
        self.assertEqual(ttl_adapted, 6000.0)

        # Ensure hard floor applies
        ttl_floor = state.compute_adaptive_tombstone_ttl(default_ttl_sec=10.0)
        # 2000.0 * 3.0 = 6000.0
        self.assertGreaterEqual(ttl_floor, 300.0)


if __name__ == "__main__":
    unittest.main()

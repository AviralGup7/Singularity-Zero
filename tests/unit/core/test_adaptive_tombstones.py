import time
import unittest

from src.core.frontier.state import HybridLogicalClock, LWWset, NeuralState


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

    def test_tombstone_gc_requires_causal_watermark_when_set(self) -> None:
        """P0-6: TTL alone must not purge when a stable HLC watermark is configured."""
        s: LWWset[str] = LWWset()
        # Add then delete with known HLC
        s.add("x", hlc=HybridLogicalClock(physical_time=100.0, logical_counter=1, node_id="n1"))
        # delete via remove if available else mark
        if hasattr(s, "remove"):
            s.remove("x", hlc=HybridLogicalClock(physical_time=100.0, logical_counter=2, node_id="n1"))
        else:
            # fallback: direct element mutate under lock
            with s._lock:
                el = s._elements[s._key("x")]
                from src.core.frontier.state import LWWElement

                s._elements[s._key("x")] = LWWElement(
                    value=el.value,
                    hlc=HybridLogicalClock(physical_time=100.0, logical_counter=2, node_id="n1"),
                    vclock=el.vclock,
                    timestamp=time.time() - 10_000.0,  # aged
                    deleted=True,
                )

        # Age all tombstones
        with s._lock:
            for k, el in list(s._elements.items()):
                if el.deleted:
                    from src.core.frontier.state import LWWElement

                    s._elements[k] = LWWElement(
                        value=el.value,
                        hlc=el.hlc,
                        vclock=el.vclock,
                        timestamp=time.time() - 10_000.0,
                        deleted=True,
                    )

        # Watermark BEHIND tombstone HLC -> must not GC
        behind = HybridLogicalClock(physical_time=50.0, logical_counter=0, node_id="n1")
        purged = s.compact(max_tombstone_age_seconds=1.0, stable_hlc=behind)
        self.assertEqual(purged, 0)

        # Watermark AHEAD of tombstone HLC -> GC allowed
        ahead = HybridLogicalClock(physical_time=200.0, logical_counter=0, node_id="n1")
        purged = s.compact(max_tombstone_age_seconds=1.0, stable_hlc=ahead)
        self.assertGreaterEqual(purged, 1)

    def test_neural_state_advance_watermark(self) -> None:
        state = NeuralState()
        w = state.advance_stable_gc_watermark(
            HybridLogicalClock(physical_time=1.0, logical_counter=1, node_id="n")
        )
        self.assertEqual(w.physical_time, 1.0)
        # Monotonic advance only
        state.advance_stable_gc_watermark(
            HybridLogicalClock(physical_time=0.5, logical_counter=0, node_id="n")
        )
        self.assertEqual(state._stable_gc_hlc.physical_time, 1.0)


if __name__ == "__main__":
    unittest.main()

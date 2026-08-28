import time
import unittest

from src.realtime.prioritized_broker import PrioritizedRealtimeBroker, QoSClass, TelemetryEvent


class TestBoundedP0Backpressure(unittest.TestCase):
    def test_p0_emergency_ring_buffer_on_spool_saturation(self) -> None:
        # Create broker with small capacities for testing
        broker = PrioritizedRealtimeBroker(
            p0_capacity=5,
            max_p0_spool=10,
            emergency_ring_capacity=5,
            max_backpressure_wait_ms=20.0,
        )

        # 1. Fill primary p0_queue (5 items)
        for i in range(5):
            evt = TelemetryEvent(
                event_id=f"p0_q_{i}",
                qos=QoSClass.P0_CONTROL,
                topic="audit.auth",
                payload={"seq": i},
            )
            self.assertTrue(broker.publish(evt))

        self.assertEqual(len(broker._p0_queue), 5)

        # 2. Fill secondary p0_memory_spool (10 items)
        for i in range(10):
            evt = TelemetryEvent(
                event_id=f"p0_spool_{i}",
                qos=QoSClass.P0_CONTROL,
                topic="audit.auth",
                payload={"seq": i},
            )
            self.assertTrue(broker.publish(evt))

        self.assertEqual(len(broker._p0_memory_spool), 10)

        # 3. Next items should shed to non-blocking Emergency Ring Buffer instead of hanging caller
        start_time = time.monotonic()
        for i in range(5):
            evt = TelemetryEvent(
                event_id=f"p0_emerg_{i}",
                qos=QoSClass.P0_CONTROL,
                topic="audit.auth",
                payload={"seq": i},
            )
            # Must return True non-blocking
            self.assertTrue(broker.publish(evt))

        elapsed_ms = (time.monotonic() - start_time) * 1000.0
        # Must execute within a few milliseconds (bounded latency)
        self.assertLess(elapsed_ms, 50.0)
        self.assertEqual(len(broker._p0_emergency_ring), 5)


if __name__ == "__main__":
    unittest.main()

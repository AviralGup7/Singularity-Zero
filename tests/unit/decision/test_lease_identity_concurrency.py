import time
import unittest

from src.decision.models import CandidateLease
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget


class TestCandidateLeaseIdentityConcurrency(unittest.TestCase):
    def test_lease_batch_returns_candidate_leases(self):
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://api.example.com/v1", base_priority=10.0))
        queue.push(ScanTarget(url="https://api.example.com/v2", base_priority=20.0))

        leases = queue.lease_batch(limit=2, lease_timeout_seconds=30.0, worker_id="worker_01", execution_id="exec_1")
        self.assertEqual(len(leases), 2)
        self.assertIsInstance(leases[0], CandidateLease)
        self.assertEqual(leases[0].target_url, "https://api.example.com/v2")  # Highest priority first
        self.assertEqual(leases[0].worker_id, "worker_01")
        self.assertEqual(leases[0].execution_id, "exec_1")
        self.assertTrue(leases[0].lease_id.startswith("lease_"))

        # While leased, queue.peek_batch() should not return in-flight leases
        peeked = queue.peek_batch(limit=10)
        self.assertEqual(len(peeked), 0)

    def test_ack_batch_verifies_lease_identity_and_rejects_stale_worker(self):
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://api.example.com/item", base_priority=50.0))

        # 1. Worker A leases target with a 0.05s timeout
        lease_a = queue.lease_batch(limit=1, lease_timeout_seconds=0.05, worker_id="worker_A")[0]
        self.assertIsNotNone(lease_a)

        # Wait for lease A to expire
        time.sleep(0.06)

        # 2. Worker B re-leases target after TTL expiry
        lease_b = queue.lease_batch(limit=1, lease_timeout_seconds=30.0, worker_id="worker_B")[0]
        self.assertNotEqual(lease_a.lease_id, lease_b.lease_id)

        # 3. Worker A (stale) attempts to acknowledge completed execution
        acked = queue.ack_batch([lease_a])
        self.assertEqual(acked, 0)  # Stale ack rejected!

        # Target must still not be scanned
        target = queue._url_map.get("https://api.example.com/item")
        self.assertIsNotNone(target)
        self.assertFalse(target.scanned)

        # 4. Worker B (holding active lease) acknowledges
        acked_b = queue.ack_batch([lease_b])
        self.assertEqual(acked_b, 1)
        self.assertTrue(target.scanned)

    def test_release_batch_with_identity(self):
        queue = CorrelationPriorityQueue()
        queue.push(ScanTarget(url="https://api.example.com/test", base_priority=15.0))

        lease = queue.lease_batch(limit=1, lease_timeout_seconds=60.0, worker_id="worker_X")[0]
        self.assertEqual(len(queue.peek_batch()), 0)

        # Release with correct lease
        released = queue.release_batch([lease])
        self.assertEqual(released, 1)

        # Target should now be available immediately again
        peeked = queue.peek_batch(limit=1)
        self.assertEqual(len(peeked), 1)
        self.assertEqual(peeked[0], "https://api.example.com/test")

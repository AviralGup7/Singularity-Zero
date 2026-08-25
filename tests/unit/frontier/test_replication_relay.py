import unittest

from src.infrastructure.frontier.replication import WALReplicationRelay


class TestWALReplicationRelay(unittest.TestCase):
    def test_relay_initialization_and_empty_peer_replicate(self):
        relay = WALReplicationRelay(
            local_wal=None,
            peer_redis_urls=[],
            run_id="test_run_01",
        )

        entry = {"execution_id": "exec_01", "outcome": "COMPLETED"}
        res = relay.replicate_entry(entry)
        self.assertEqual(res, {})

        deltas = relay.pull_peer_deltas("redis://nonexistent:6379/0")
        self.assertEqual(deltas, [])

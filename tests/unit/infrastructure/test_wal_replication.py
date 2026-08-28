"""Unit tests for WALReplicationRelay monotonic ordering, cursors, backpressure, and lag gating."""

from __future__ import annotations

import json
import time
import unittest
from unittest.mock import MagicMock

from src.infrastructure.frontier.replication import (
    ReplicationLagExceededError,
    WALReplicationRelay,
)


class TestWALReplicationRelay(unittest.TestCase):
    """Verify that WALReplicationRelay enforces monotonic read ordering and fail-closed lag gate."""

    def setUp(self) -> None:
        self.mock_wal = MagicMock()
        self.peer_url = "redis://peer.region-b:6379/0"
        self.relay = WALReplicationRelay(
            local_wal=self.mock_wal,
            peer_redis_urls=[self.peer_url],
            run_id="run-test-relay",
            max_lag_seconds_threshold=5.0,
            backpressure_max_queue=500,
        )

    def test_replicate_entry_assigns_monotonic_sequence_and_trims_queue(self) -> None:
        mock_client = MagicMock()
        self.relay._peer_clients[self.peer_url] = mock_client

        entry1 = {"event": "HOST_DISCOVERED", "host": "api.example.com"}
        entry2 = {"event": "URL_CRAWLED", "url": "https://api.example.com/v1"}

        res1 = self.relay.replicate_entry(entry1)
        res2 = self.relay.replicate_entry(entry2)

        self.assertTrue(res1[self.peer_url])
        self.assertTrue(res2[self.peer_url])
        self.assertEqual(self.relay._outbound_seq, 2)

        # Verify xadd called with backpressure maxlen
        self.assertEqual(mock_client.xadd.call_count, 2)
        call_args = mock_client.xadd.call_args_list[0]
        self.assertEqual(call_args.kwargs.get("maxlen"), 500)
        self.assertTrue(call_args.kwargs.get("approximate"))

    def test_pull_peer_deltas_enforces_monotonic_sequence(self) -> None:
        mock_client = MagicMock()
        self.relay._peer_clients[self.peer_url] = mock_client

        # Mock incoming stream with retrograde sequence: seq 1, seq 2, seq 1 (duplicate/stale), seq 3
        now = time.time()
        stream_messages = [
            ("1000-1", {b"delta": json.dumps({"_seq": 1, "host": "h1", "_src_ts": now}).encode()}),
            ("1000-2", {b"delta": json.dumps({"_seq": 2, "host": "h2", "_src_ts": now}).encode()}),
            ("1000-3", {b"delta": json.dumps({"_seq": 1, "host": "h1-stale", "_src_ts": now}).encode()}),
            ("1000-4", {b"delta": json.dumps({"_seq": 3, "host": "h3", "_src_ts": now}).encode()}),
        ]
        mock_client.xread.return_value = [("cyber:wal:run-test-relay", stream_messages)]

        deltas = self.relay.pull_peer_deltas(self.peer_url)

        # Retrograde seq 1 must be dropped
        self.assertEqual(len(deltas), 3)
        self.assertEqual([d["_seq"] for d in deltas], [1, 2, 3])

        # Verify resumable cursor updated
        cursor = self.relay.get_cursor(self.peer_url)
        self.assertEqual(cursor.last_stream_id, "1000-4")
        self.assertEqual(cursor.last_seq, 3)

    def test_fail_closed_lag_gate_raises_when_lag_exceeds_threshold(self) -> None:
        cursor = self.relay.get_cursor(self.peer_url)
        cursor.last_replicated_ts = time.time() - 15.0  # 15s ago, threshold is 5.0s

        self.assertGreater(self.relay.get_replication_lag_seconds(self.peer_url), 10.0)

        with self.assertRaises(ReplicationLagExceededError):
            self.relay.assert_replication_fresh(self.peer_url)

        with self.assertRaises(ReplicationLagExceededError):
            self.relay.pull_peer_deltas(self.peer_url, enforce_lag_gate=True)

    def test_reconcile_with_peer_filters_mutating_settlements_i36(self) -> None:
        mock_client = MagicMock()
        self.relay._peer_clients[self.peer_url] = mock_client

        now = time.time()
        stream_messages = [
            ("1000-1", {b"delta": json.dumps({"_seq": 1, "host": "target1", "_src_ts": now}).encode()}),
            ("1000-2", {b"delta": json.dumps({"_seq": 2, "_is_settlement_intent": True, "_src_ts": now}).encode()}),
            ("1000-3", {b"delta": json.dumps({"_seq": 3, "command_type": "APPLY_MUTATION", "_src_ts": now}).encode()}),
            ("1000-4", {b"delta": json.dumps({"_seq": 4, "scan_discovery": "vuln_found", "_src_ts": now}).encode()}),
        ]
        mock_client.xread.return_value = [("cyber:wal:run-test-relay", stream_messages)]

        journal_count = self.relay.reconcile_with_peer(self.peer_url)

        # Mutating settlement intent and command must be refused (I36 single-writer)
        self.assertEqual(journal_count, 2)


if __name__ == "__main__":
    unittest.main()

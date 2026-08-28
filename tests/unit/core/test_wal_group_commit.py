import tempfile
import unittest

from src.core.contracts.command_envelope import CommandEnvelope, CommandResult
from src.core.frontier.replicated_log import CommittedEntry, PartitionWAL


class TestWALGroupCommit(unittest.TestCase):
    def test_group_commit_batching_and_flush(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wal = PartitionWAL(
                partition_id="P-0001",
                node_id="node-1",
                wal_dir=tmpdir,
                group_commit=True,
                group_commit_batch_size=10,
                group_commit_window_ms=50.0,
            )

            res = CommandResult(
                status="SUCCESS",
                aggregate_id="P-0001",
                resulting_aggregate_version=1,
                result_code="OK",
            )
            # Append 5 entries (less than batch size 10)
            for i in range(1, 6):
                cmd = CommandEnvelope(
                    command_id=f"cmd_{i}",
                    command_type="SET_VALUE",
                    aggregate_id="P-0001",
                    payload={"idx": i},
                    correlation_id=f"corr_{i}",
                    causation_id=f"caus_{i}",
                )
                entry = CommittedEntry(
                    partition_id="P-0001",
                    raft_term=1,
                    raft_index=i,
                    entry_hash=f"hash_{i}",
                    previous_entry_hash=f"hash_{i-1}",
                    command=cmd,
                    transition_result=res,
                )
                wal.append_entry(entry, committed=True, sync=True)

            # Pending buffer holds 5 records
            self.assertEqual(len(wal._pending_buffer), 5)

            # Append remaining 5 entries -> triggers batch size 10 automatic group commit flush
            for i in range(6, 11):
                cmd = CommandEnvelope(
                    command_id=f"cmd_{i}",
                    command_type="SET_VALUE",
                    aggregate_id="P-0001",
                    payload={"idx": i},
                    correlation_id=f"corr_{i}",
                    causation_id=f"caus_{i}",
                )
                entry = CommittedEntry(
                    partition_id="P-0001",
                    raft_term=1,
                    raft_index=i,
                    entry_hash=f"hash_{i}",
                    previous_entry_hash=f"hash_{i-1}",
                    command=cmd,
                    transition_result=res,
                )
                wal.append_entry(entry, committed=True, sync=True)

            self.assertEqual(len(wal._pending_buffer), 0)

            # Load all entries from disk to verify CRC-64 verification across group-committed batch
            loaded = wal.load_all_entries()
            self.assertEqual(len(loaded), 10)
            self.assertEqual(loaded[0][0].raft_index, 1)
            self.assertEqual(loaded[9][0].raft_index, 10)


if __name__ == "__main__":
    unittest.main()

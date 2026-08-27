import unittest

from src.core.frontier.state import NeuralState
from src.core.frontier.state_authority import SettlementIntent, StateAuthority
from tests.test_support.journal import MemoryJournal


class TestAutoCompaction(unittest.TestCase):
    def test_auto_compaction_triggered_at_interval(self):
        state = NeuralState()
        wal = MemoryJournal()

        # Mock compact_after_snapshot on MemoryJournal
        compaction_calls: list[int] = []

        def mock_compact(snap_state, **kwargs):
            compaction_calls.append(len(compaction_calls) + 1)
            return True

        wal.compact_after_snapshot = mock_compact

        # StateAuthority configured with auto_compact_interval=5
        authority = StateAuthority(
            state=state,
            wal=wal,
            auto_compact_interval=5,
        )

        # Append 12 settlement intents
        for i in range(1, 13):
            intent = SettlementIntent(
                settlement_id=f"stl_auto_{i}",
                execution_id=f"exec_auto_{i}",
                outcome="COMPLETED",
                state_delta={"urls": [f"https://example.com/{i}"]},
            )
            authority.append_settlement_intent(intent)

        # Should have triggered compaction twice (at append 5 and 10)
        self.assertEqual(len(compaction_calls), 2)
        self.assertEqual(len(wal), 12)

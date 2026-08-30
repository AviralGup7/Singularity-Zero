"""B13: FRONTIER_ONLY ingest stays CANDIDATE, not REPORTABLE."""

from __future__ import annotations

import unittest

from src.core.frontier.frontier_only import enter_frontier_only, reset_frontier_only
from src.core.frontier.state import NeuralState


class TestFrontierOnlyCandidates(unittest.TestCase):
    def tearDown(self) -> None:
        reset_frontier_only()

    def test_unstamped_finding_stays_candidate(self) -> None:
        enter_frontier_only("test", force=True)
        state = NeuralState()
        state.apply_delta(
            {"findings": [{"title": "xss", "url": "https://example.test", "category": "xss"}]}
        )
        self.assertEqual(len(state.findings), 0)
        self.assertGreaterEqual(len(state.candidates), 1)


if __name__ == "__main__":
    unittest.main()

"""I39 budget accounting mode transition atomicity."""

from __future__ import annotations

import unittest

from src.core.frontier.quota_slab import BudgetModeTransitionError, transition_accounting_mode


class TestBudgetModeTransition(unittest.TestCase):
    def test_i5_to_i26_and_back(self) -> None:
        snap = transition_accounting_mode(
            total=100, consumed=10, outstanding=20, available=70, slab_units=15, to_multi_raft=True
        )
        self.assertEqual(snap["slab_reserved"], 15)
        self.assertEqual(snap["available"], 55)
        self.assertEqual(
            snap["consumed"] + snap["outstanding"] + snap["slab_reserved"] + snap["available"],
            100,
        )
        back = transition_accounting_mode(
            total=snap["total"],
            consumed=snap["consumed"],
            outstanding=snap["outstanding"],
            available=snap["available"],
            slab_reserved=snap["slab_reserved"],
            to_multi_raft=False,
        )
        self.assertEqual(back["slab_reserved"], 0)
        self.assertEqual(back["available"], 70)

    def test_refuses_over_available(self) -> None:
        with self.assertRaises(BudgetModeTransitionError):
            transition_accounting_mode(
                total=100, consumed=10, outstanding=20, available=70, slab_units=80
            )


if __name__ == "__main__":
    unittest.main()

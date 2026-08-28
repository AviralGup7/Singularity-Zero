import unittest
from types import SimpleNamespace

from src.core.frontier.invariant_graph import ProofGraphError, verify_recovery_prerequisites


class TestRecoveryBudgetConservation(unittest.TestCase):
    def test_recovery_verifies_i5_budget_conservation(self) -> None:
        # Balanced budget: consumed(10) + outstanding(20) + available(70) == total(100)
        valid_observed = SimpleNamespace(
            recovered_tickets=(),
            recovered_settlements=(),
            recovered_identities=(),
            recovered_budget_state={"total": 100, "consumed": 10, "outstanding": 20, "available": 70},
            bus_emitted_without_outbox=False,
            live_authority_revision="",
        )
        # Should not raise
        verify_recovery_prerequisites(valid_observed)

    def test_recovery_fails_closed_on_i5_budget_imbalance(self) -> None:
        # Imbalanced budget: consumed(10) + outstanding(20) + available(60) != total(100)
        imbalanced_observed = SimpleNamespace(
            recovered_tickets=(),
            recovered_settlements=(),
            recovered_identities=(),
            recovered_budget_state={"total": 100, "consumed": 10, "outstanding": 20, "available": 60},
            bus_emitted_without_outbox=False,
            live_authority_revision="",
        )
        with self.assertRaises(ProofGraphError) as ctx:
            verify_recovery_prerequisites(imbalanced_observed)
        self.assertIn("I5", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


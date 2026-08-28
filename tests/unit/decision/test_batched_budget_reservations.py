import unittest

from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer


class TestBatchedHuntBudgetReservation(unittest.TestCase):
    def test_local_sublease_batching_reduces_fsm_cycles(self) -> None:
        budget = HuntBudget(max_requests=1000, label="test_stage")
        # Enforcer configured with batch_reservation_size=50
        enforcer = HuntBudgetEnforcer(budget=budget, batch_reservation_size=50)

        # 1st reservation: slow path -> allocates batch of 50 units
        res1 = enforcer.reserve_with_identity(count=1)
        self.assertIsNotNone(res1)
        self.assertEqual(enforcer._requests_reserved, 1)
        self.assertEqual(enforcer._local_sublease_pool_available, 49)

        # 2nd to 50th reservations: fast path -> consumes directly from local sublease pool buffer
        for i in range(2, 51):
            res = enforcer.reserve_with_identity(count=1)
            self.assertIsNotNone(res)
            self.assertEqual(enforcer._requests_reserved, i)

        self.assertEqual(enforcer._local_sublease_pool_available, 0)

        # 51st reservation: buffer empty -> automatically allocates next batch of 50
        res51 = enforcer.reserve_with_identity(count=1)
        self.assertIsNotNone(res51)
        self.assertEqual(enforcer._requests_reserved, 51)
        self.assertEqual(enforcer._local_sublease_pool_available, 49)


if __name__ == "__main__":
    unittest.main()

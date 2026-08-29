"""I28 settle vs reaper fencing token."""

from __future__ import annotations

import threading
import unittest

from src.core.frontier.lease_status import (
    LeaseFence,
    LeaseStatus,
    StaleLeaseFenceError,
    cas_lease_status,
)


class TestLeaseFence(unittest.TestCase):
    def test_cas_refuses_stale(self) -> None:
        cas_lease_status(LeaseStatus.ACTIVE, LeaseStatus.CONSUMED, fence=1, expected_fence=1)
        with self.assertRaises(StaleLeaseFenceError):
            cas_lease_status(LeaseStatus.ACTIVE, LeaseStatus.EXPIRED, fence=1, expected_fence=2)

    def test_only_one_of_consumed_or_expired_wins(self) -> None:
        fence = LeaseFence()
        fence.bind("lease-1", LeaseStatus.ACTIVE)
        errors: list[BaseException] = []
        winners: list[LeaseStatus] = []

        def settle() -> None:
            try:
                winners.append(fence.cas("lease-1", LeaseStatus.CONSUMED))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        def expire() -> None:
            try:
                winners.append(fence.cas("lease-1", LeaseStatus.EXPIRED))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        t1 = threading.Thread(target=settle)
        t2 = threading.Thread(target=expire)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], (StaleLeaseFenceError, ValueError))
        self.assertIn(winners[0], {LeaseStatus.CONSUMED, LeaseStatus.EXPIRED})


if __name__ == "__main__":
    unittest.main()

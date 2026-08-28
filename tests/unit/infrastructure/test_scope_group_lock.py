import unittest

from src.infrastructure.task_pool import ScopeGroupLock, derive_scope_group


class TestScopeGroupLocking(unittest.TestCase):
    def test_derive_scope_group(self) -> None:
        self.assertEqual(derive_scope_group("api.example.com"), "example.com")
        self.assertEqual(
            derive_scope_group("https://admin.staging.example.com:8443"), "example.com"
        )
        self.assertEqual(derive_scope_group("192.168.1.10"), "192.168.1.10")

    def test_concurrent_overlapping_subdomains_blocked(self) -> None:
        lock1 = ScopeGroupLock()
        lock2 = ScopeGroupLock()

        # Scan 1 acquires lock on api.example.com (scope_group: example.com)
        acquired1 = lock1.acquire("api.example.com")
        self.assertTrue(acquired1)

        # Scan 2 attempts concurrent scan on www.example.com (same scope_group: example.com)
        acquired2 = lock2.acquire("www.example.com")
        # Must be blocked by scope_group lock!
        self.assertFalse(acquired2)

        # Once Scan 1 releases, Scan 2 can acquire
        lock1.release()
        acquired2_after = lock2.acquire("www.example.com")
        self.assertTrue(acquired2_after)
        lock2.release()


if __name__ == "__main__":
    unittest.main()

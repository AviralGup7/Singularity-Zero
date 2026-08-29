"""I38 tenant isolation."""

from __future__ import annotations

import unittest

from src.core.frontier.tenant_isolation import TenantIsolationError, assert_tenant_scope


class TestTenantIsolation(unittest.TestCase):
    def test_same_tenant_ok(self) -> None:
        assert_tenant_scope(resource_tenant="t1", actor_tenant="t1")

    def test_cross_tenant_refused(self) -> None:
        with self.assertRaises(TenantIsolationError):
            assert_tenant_scope(resource_tenant="t1", actor_tenant="t2")

    def test_empty_tenant_fail_closed(self) -> None:
        with self.assertRaises(TenantIsolationError):
            assert_tenant_scope(resource_tenant="t1", actor_tenant="")
        with self.assertRaises(TenantIsolationError):
            assert_tenant_scope(resource_tenant="", actor_tenant="t1")


if __name__ == "__main__":
    unittest.main()

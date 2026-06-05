"""Unit tests for src.core.tenant_context."""

import asyncio
import logging
import threading
import unittest

import pytest

from src.core.tenant_context import TenantContext


@pytest.mark.unit
class TestCurrentTenant(unittest.TestCase):
    def setUp(self) -> None:
        try:
            with TenantContext.scope(None):
                pass
        except Exception:
            logging.getLogger(__name__).exception("TenantContext setup failed")

    def tearDown(self) -> None:
        try:
            with TenantContext.scope(None):
                pass
        except Exception:
            logging.getLogger(__name__).exception("TenantContext teardown failed")

    def test_default_tenant_is_none(self) -> None:
        self.assertIsNone(TenantContext.get_current_tenant())

    def test_scope_sets_tenant(self) -> None:
        with TenantContext.scope("tenant-a"):
            self.assertEqual(TenantContext.get_current_tenant(), "tenant-a")

    def test_scope_restores_on_exit(self) -> None:
        with TenantContext.scope("tenant-a"):
            pass
        self.assertIsNone(TenantContext.get_current_tenant())

    def test_nested_scope_restores_outer(self) -> None:
        with TenantContext.scope("outer"):
            with TenantContext.scope("inner"):
                self.assertEqual(TenantContext.get_current_tenant(), "inner")
            self.assertEqual(TenantContext.get_current_tenant(), "outer")
        self.assertIsNone(TenantContext.get_current_tenant())

    def test_set_via_explicit_assignment(self) -> None:
        token = TenantContext.set_current_tenant("explicit-tenant")
        try:
            self.assertEqual(TenantContext.get_current_tenant(), "explicit-tenant")
        finally:
            TenantContext.reset_current_tenant(token)
        self.assertIsNone(TenantContext.get_current_tenant())


@pytest.mark.unit
class TestScopeThreadIsolation(unittest.TestCase):
    def test_scope_does_not_leak_across_threads(self) -> None:
        results: list[str | None] = []
        barrier = threading.Barrier(2)

        def worker() -> None:
            barrier.wait()
            with TenantContext.scope("thread-tenant"):
                barrier.wait()
                results.append(TenantContext.get_current_tenant())
            results.append(TenantContext.get_current_tenant())

        t = threading.Thread(target=worker)
        t.start()
        with TenantContext.scope("main-tenant"):
            barrier.wait()
            main_tenant_during_thread = TenantContext.get_current_tenant()
        barrier.wait()
        t.join()

        self.assertEqual(main_tenant_during_thread, "main-tenant")
        self.assertEqual(results[0], "thread-tenant")
        self.assertIsNone(results[1])


@pytest.mark.unit
class TestScopeAsyncIsolation(unittest.TestCase):
    def test_scope_isolated_across_concurrent_tasks(self) -> None:
        async def main() -> dict[str, str | None]:
            results: dict[str, str | None] = {}

            async def task(name: str, delay: float) -> None:
                with TenantContext.scope(name):
                    await asyncio.sleep(delay)
                    results[name] = TenantContext.get_current_tenant()

            await asyncio.gather(task("a", 0.02), task("b", 0.0))
            results["__outside__"] = TenantContext.get_current_tenant()
            return results

        results = asyncio.run(main())
        self.assertEqual(results["a"], "a")
        self.assertEqual(results["b"], "b")
        self.assertIsNone(results["__outside__"])


@pytest.mark.unit
class TestTenantContextHelpers(unittest.TestCase):
    def test_set_returns_token(self) -> None:
        token = TenantContext.set_current_tenant("xyz")
        try:
            self.assertIsNotNone(token)
        finally:
            TenantContext.reset_current_tenant(token)

    def test_reset_using_token_restores(self) -> None:
        TenantContext.set_current_tenant("outer")
        token = TenantContext.set_current_tenant("inner")
        self.assertEqual(TenantContext.get_current_tenant(), "inner")
        TenantContext.reset_current_tenant(token)
        self.assertEqual(TenantContext.get_current_tenant(), "outer")


if __name__ == "__main__":
    unittest.main()

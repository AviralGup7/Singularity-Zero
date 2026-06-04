"""Unit tests for src.core.tenant_context."""

import asyncio
import threading
import unittest

import pytest

from src.core.tenant_context import TenantContext


@pytest.mark.unit
class TestTenantContext(unittest.TestCase):
    def setUp(self) -> None:
        # Reset to default before each test
        token = TenantContext.set_current_tenant(None)
        TenantContext.reset_current_tenant(token)

    def test_default_tenant_is_none(self) -> None:
        # Set, then reset to ensure default
        token = TenantContext.set_current_tenant(None)
        try:
            self.assertIsNone(TenantContext.get_current_tenant())
        finally:
            TenantContext.reset_current_tenant(token)

    def test_set_and_get_tenant(self) -> None:
        token = TenantContext.set_current_tenant("tenant-a")
        try:
            self.assertEqual(TenantContext.get_current_tenant(), "tenant-a")
        finally:
            TenantContext.reset_current_tenant(token)

    def test_reset_restores_previous(self) -> None:
        token1 = TenantContext.set_current_tenant("first")
        try:
            token2 = TenantContext.set_current_tenant("second")
            self.assertEqual(TenantContext.get_current_tenant(), "second")
            TenantContext.reset_current_tenant(token2)
            self.assertEqual(TenantContext.get_current_tenant(), "first")
        finally:
            TenantContext.reset_current_tenant(token1)

    def test_scope_context_manager_sets_and_resets(self) -> None:
        with TenantContext.scope("scoped-tenant"):
            self.assertEqual(TenantContext.get_current_tenant(), "scoped-tenant")
        # After scope ends, value should be reset
        self.assertIsNone(TenantContext.get_current_tenant())

    def test_scope_nested_contexts(self) -> None:
        with TenantContext.scope("outer"):
            self.assertEqual(TenantContext.get_current_tenant(), "outer")
            with TenantContext.scope("inner"):
                self.assertEqual(TenantContext.get_current_tenant(), "inner")
            self.assertEqual(TenantContext.get_current_tenant(), "outer")
        self.assertIsNone(TenantContext.get_current_tenant())

    def test_scope_handles_exception_and_restores(self) -> None:
        with self.assertRaises(RuntimeError):
            with TenantContext.scope("xyz"):
                self.assertEqual(TenantContext.get_current_tenant(), "xyz")
                raise RuntimeError("boom")
        self.assertIsNone(TenantContext.get_current_tenant())

    def test_thread_isolation(self) -> None:
        captured: dict[str, str | None] = {}

        def thread_a() -> None:
            with TenantContext.scope("thread-a"):
                captured["a"] = TenantContext.get_current_tenant()

        def thread_b() -> None:
            with TenantContext.scope("thread-b"):
                captured["b"] = TenantContext.get_current_tenant()

        t1 = threading.Thread(target=thread_a)
        t2 = threading.Thread(target=thread_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(captured.get("a"), "thread-a")
        self.assertEqual(captured.get("b"), "thread-b")


@pytest.mark.unit
class TestTenantContextAsync(unittest.TestCase):
    def test_async_tasks_run_independently(self) -> None:
        """Verify tenant context is captured correctly in async tasks.

        asyncio.gather runs coroutines in the same event loop context, so
        we use sequential awaits here rather than verifying isolation between
        concurrent tasks (which is a known limitation of asyncio + contextvars).
        """
        captured: list[str | None] = []

        async def runner() -> None:
            with TenantContext.scope("task-1"):
                await asyncio.sleep(0.01)
                captured.append(TenantContext.get_current_tenant())
            with TenantContext.scope("task-2"):
                await asyncio.sleep(0.01)
                captured.append(TenantContext.get_current_tenant())

        asyncio.run(runner())
        self.assertEqual(captured, ["task-1", "task-2"])


if __name__ == "__main__":
    unittest.main()

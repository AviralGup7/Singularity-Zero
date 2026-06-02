import asyncio

import pytest

from src.core.frontier.proc_pool import FrontierProcessPool


def test_proc_pool_can_be_constructed_without_running_loop():
    pool = FrontierProcessPool(pool_size=1)
    assert pool._watchdog_started is False


@pytest.mark.asyncio
async def test_proc_pool_warm_and_cleanup(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)

    async def mock_create_subprocess_exec(*args, **kwargs):
        class MockProcess:
            pid = 1234

            def terminate(self):
                pass

            async def wait(self):
                return 0

        return MockProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", mock_create_subprocess_exec)

    await pool.warm_pool("dummy_tool", [])
    assert len(pool._processes) == 1

    monkeypatch.setattr("os.killpg", lambda *args: None, raising=False)
    monkeypatch.setattr("os.getpgid", lambda *args: 1, raising=False)

    await pool.cleanup()
    assert len(pool._processes) == 0


@pytest.mark.asyncio
async def test_proc_pool_cleanup_waits_for_children(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)
    waited = False

    async def mock_create_subprocess_exec(*args, **kwargs):
        class MockProcess:
            pid = 1234
            current_task_id = None

            def terminate(self):
                pass

            async def wait(self):
                nonlocal waited
                waited = True
                return 0

        return MockProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", mock_create_subprocess_exec)
    monkeypatch.setattr("os.killpg", lambda *args: None, raising=False)
    monkeypatch.setattr("os.getpgid", lambda *args: 1, raising=False)

    await pool.warm_pool("dummy_tool", [])
    await pool.cleanup()
    assert waited is True

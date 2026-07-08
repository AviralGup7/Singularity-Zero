import asyncio

import pytest

from src.core.frontier.proc_pool import FrontierProcessPool


def test_proc_pool_can_be_constructed_without_running_loop():
    pool = FrontierProcessPool(pool_size=1)
    assert pool.pool_size == 1


@pytest.mark.asyncio
async def test_proc_pool_warm_verifies_tool(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)

    monkeypatch.setattr("src.core.frontier.proc_pool._validate_tool_name", lambda _: None)
    monkeypatch.setattr(
        "src.core.frontier.proc_pool.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr(pool, "_detect_version", lambda path: "1.0.0")

    await pool.warm_pool("dummy_tool", ["--default-arg"])
    assert pool._base_args_map["dummy_tool"] == ["--default-arg"]
    assert pool._tool_versions["dummy_tool"].verified is True
    assert pool._tool_versions["dummy_tool"].version == "1.0.0"


@pytest.mark.asyncio
async def test_proc_pool_warm_warns_on_missing_tool(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)

    monkeypatch.setattr("src.core.frontier.proc_pool._validate_tool_name", lambda _: None)
    monkeypatch.setattr("src.core.frontier.proc_pool.shutil.which", lambda name: None)

    await pool.warm_pool("missing_tool", [])
    assert pool._tool_versions["missing_tool"].verified is False


@pytest.mark.asyncio
async def test_proc_pool_cleanup_clears_state(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)
    pool._base_args_map["tool"] = ["--arg"]
    pool._task_receipts["task1"] = pool._make_receipt("task1", "tool", "completed")

    await pool.cleanup()
    assert len(pool._task_receipts) == 0
    assert len(pool._binary_task_cache) == 0
    assert len(pool._base_args_map) == 0


@pytest.mark.asyncio
async def test_proc_pool_verify_all_tools(monkeypatch):
    pool = FrontierProcessPool(pool_size=1)

    monkeypatch.setattr("src.core.frontier.proc_pool._validate_tool_name", lambda _: None)

    def mock_which(name):
        if name in ("nuclei", "httpx"):
            return f"/usr/bin/{name}"
        return None

    monkeypatch.setattr("src.core.frontier.proc_pool.shutil.which", mock_which)
    monkeypatch.setattr(pool, "_detect_version", lambda path: "2.0.0")

    results = pool.verify_all_tools(["nuclei", "httpx", "subfinder"])
    assert results["nuclei"].verified is True
    assert results["httpx"].verified is True
    assert results["subfinder"].verified is False


@pytest.mark.asyncio
async def test_proc_pool_semaphore_bounds_concurrency(monkeypatch):
    pool = FrontierProcessPool(max_concurrent=2)
    assert pool._semaphore._value == 2

    running = []
    max_observed = 0

    async def slow_exec(*args, **kwargs):
        nonlocal max_observed
        running.append(1)
        if len(running) > max_observed:
            max_observed = len(running)
        await asyncio.sleep(0.1)
        running.pop()
        return "done"

    monkeypatch.setattr("src.core.frontier.proc_pool._validate_tool_name", lambda _: None)
    monkeypatch.setattr(pool, "_execute_task_inner", slow_exec)

    tasks = [pool.execute_task("tool", f"task_{i}") for i in range(4)]
    results = await asyncio.gather(*tasks)

    assert all(r == "done" for r in results)
    assert max_observed <= 2

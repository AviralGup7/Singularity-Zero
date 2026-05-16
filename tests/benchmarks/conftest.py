"""Benchmark fixtures and configuration for the cyber security test pipeline.

Provides shared fixtures for Redis, queue, cache, executor, and dashboard
instances used across all benchmark test modules.
"""

import asyncio
import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

collect_ignore_glob = ["load_test.py"]


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers for benchmark tests."""
    config.addinivalue_line(
        "markers",
        "queue: benchmarks for the queue_system package",
    )
    config.addinivalue_line(
        "markers",
        "cache: benchmarks for the cache_layer package",
    )
    config.addinivalue_line(
        "markers",
        "api: benchmarks for the fastapi_dashboard package",
    )
    config.addinivalue_line(
        "markers",
        "execution: benchmarks for the execution_engine package",
    )
    config.addinivalue_line(
        "markers",
        "websocket: benchmarks for the websocket_server package",
    )
    config.addinivalue_line(
        "markers",
        "slow: benchmarks that take longer than 1 second",
    )


def pytest_benchmark_update_json(
    config: pytest.Config,
    benchmarks: list[dict[str, Any]],
    output_json: dict[str, Any],
) -> None:
    """Add environment metadata to benchmark output."""
    import platform

    output_json["pipeline_info"] = {
        "python": platform.python_version(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "benchmark_env": os.environ.get("BENCHMARK_ENV", "local"),
    }


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop]:
    """Create a session-scoped event loop for async fixtures."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL for benchmarks.

    Uses BENCHMARK_REDIS_URL env var if set, otherwise defaults to local Redis.
    Falls back to in-memory mode if no Redis is available.
    """
    return os.environ.get("BENCHMARK_REDIS_URL", "redis://localhost:6379/1")


@pytest.fixture
def redis_client(redis_url: str):
    """Create a RedisClient for benchmarks."""
    from src.infrastructure.queue.redis_client import RedisClient

    client = RedisClient(url=redis_url, db=1, max_connections=10)
    yield client
    client.close()


@pytest_asyncio.fixture
async def job_queue(redis_client):
    """Create a JobQueue instance for benchmarks."""
    from src.infrastructure.queue.job_queue import JobQueue

    queue = JobQueue(redis_client, queue_name="benchmark_test")
    yield queue

    # Cleanup: flush benchmark keys
    if redis_client.client:
        try:
            for key in redis_client.client.scan_iter("queue:benchmark_test:*"):
                redis_client.client.delete(key)
        except Exception:  # noqa: S110
            pass


@pytest.fixture
def cache_manager():
    """Create a CacheManager for benchmarks with temp storage."""
    from src.infrastructure.cache import CacheManager
    from src.infrastructure.cache.config import CacheConfig

    with tempfile.TemporaryDirectory() as tmpdir:
        config = CacheConfig(
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            max_entries=50000,
            default_ttl=3600,
            sqlite_db_path=str(Path(tmpdir) / "bench_cache.db"),
            cache_dir=str(Path(tmpdir) / "cache_files"),
        )
        mgr = CacheManager(config)
        yield mgr
        mgr.close()


@pytest.fixture
def execution_config():
    """Create an ExecutionConfig for benchmarks."""
    from src.infrastructure.execution_engine.models import ExecutionConfig, ResourcePool

    return ExecutionConfig(
        max_workers=10,
        max_cpu_workers=2,
        default_timeout_seconds=30.0,
        default_retries=0,
        resource_pools={
            "default": ResourcePool(name="default", max_concurrent=10),
            "network": ResourcePool(name="network", max_concurrent=50),
            "cpu": ResourcePool(name="cpu", max_concurrent=2),
        },
        enable_load_balancing=False,
        enable_progress_callbacks=False,
    )


@pytest.fixture
def concurrent_executor(execution_config):
    """Create a ConcurrentExecutor for benchmarks."""
    from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor

    return ConcurrentExecutor(execution_config)


@pytest.fixture
def dashboard_config():
    """Create a DashboardConfig for benchmarks."""
    from pathlib import Path

    from src.dashboard.fastapi.config import DashboardConfig

    with tempfile.TemporaryDirectory() as tmpdir:
        output_root = Path(tmpdir) / "output"
        output_root.mkdir(parents=True, exist_ok=True)
        (output_root / "cache").mkdir(exist_ok=True)

        config = DashboardConfig(
            host="127.0.0.1",
            port=0,
            debug=False,
            workers=1,
            output_root=output_root,
            workspace_root=Path(__file__).resolve().parent.parent,
            cache_db_path=str(output_root / "cache" / "bench.db"),
            cache_dir=str(output_root / "cache"),
            rate_limit_default=100000,
            rate_limit_jobs=100000,
            rate_limit_replay=100000,
        )
        yield config


@pytest.fixture
def dashboard_app(dashboard_config):
    """Create a FastAPI test client for benchmarks."""
    from fastapi.testclient import TestClient

    from src.dashboard.fastapi.app import create_app

    app = create_app(dashboard_config)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def connection_manager():
    """Create a ConnectionManager for WebSocket benchmarks."""
    from src.websocket_server.manager import ConnectionManager

    return ConnectionManager(
        max_connections_per_user=10,
        max_connections_per_ip=20,
        stale_timeout=60.0,
    )


@pytest.fixture
def small_url_set() -> list[str]:
    """Return a small set of URLs for benchmarks (< 50)."""
    return [
        "http://testphp.vulnweb.com/index.php",
        "http://testphp.vulnweb.com/listproducts.php",
        "http://testphp.vulnweb.com/artists.php",
        "http://testphp.vulnweb.com/categories.php",
        "http://testphp.vulnweb.com/login.php",
        "http://testphp.vulnweb.com/search.php",
        "http://testphp.vulnweb.com/guestbook.php",
        "http://testphp.vulnweb.com/AJAX/index.php",
        "http://testphp.vulnweb.com/hpp/example.php",
        "http://testphp.vulnweb.com/disclaimer.php",
    ]


@pytest.fixture
def medium_url_set() -> list[str]:
    """Return a medium set of URLs for benchmarks (50-500)."""
    return [f"http://medium-target.com/page/{i}" for i in range(200)]


@pytest.fixture
def large_url_set() -> list[str]:
    """Return a large set of URLs for benchmarks (500+)."""
    return [f"http://large-target.com/path/{i}/resource" for i in range(1000)]


@pytest.fixture
def multi_target_payload() -> list[dict[str, Any]]:
    """Return multi-target scan payloads for benchmarks."""
    return [
        {
            "name": f"target_{i}",
            "urls": [f"http://target-{i}.com/page/{j}" for j in range(50)],
        }
        for i in range(10)
    ]

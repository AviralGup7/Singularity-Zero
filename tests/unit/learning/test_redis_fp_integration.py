import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.learning.fp_tracker import FPTracker
from src.learning.models.fp_pattern import FPPattern
from src.learning.repositories.redis_fp_repo import RedisFPRepository


@pytest.mark.asyncio
async def test_redis_fp_repo_upsert_and_get():
    # Note: Requires a running redis or a mock
    # For now we use a mock for the redis client inside the repo
    repo = RedisFPRepository("redis://localhost:6379/0")
    repo._client = AsyncMock()

    pattern = FPPattern.create(category="test-cat", status_codes={403}, body_indicators=["blocked"])

    await repo.upsert_pattern(pattern)
    assert repo._client.hset.called

    repo._client.hget.return_value = json.dumps(pattern.to_db_row())
    fetched = await repo.get_pattern(pattern.pattern_id)
    assert fetched.pattern_id == pattern.pattern_id
    assert fetched.category == "test-cat"


@pytest.mark.asyncio
async def test_fp_tracker_uses_redis_repo():
    mock_store = MagicMock()
    mock_redis_repo = MagicMock()
    mock_redis_repo.list_patterns = AsyncMock(
        return_value=[
            FPPattern.create(
                category="redis-cat", status_codes={429}, body_indicators=["rate limit"]
            )
        ]
    )

    tracker = FPTracker(store=mock_store, redis_repo=mock_redis_repo)

    # Execution
    await tracker._ensure_loaded_async()

    # Verification
    assert "redis-cat" in [p.category for p in tracker._cache.values()]
    assert mock_redis_repo.list_patterns.called


@pytest.mark.asyncio
async def test_fp_tracker_updates_redis_repo_on_run_update():
    mock_store = MagicMock()
    mock_redis_repo = MagicMock()
    mock_redis_repo.list_patterns = AsyncMock(return_value=[])
    mock_redis_repo.upsert_pattern = AsyncMock()

    # Mock findings from run
    mock_store.get_findings_for_run.return_value = [
        {
            "response_status": 403,
            "evidence": "Access Denied by WAF",
            "category": "xss",
            "decision": "DROP",
            "lifecycle_state": "DISCOVERED",
        }
    ]

    tracker = FPTracker(store=mock_store, redis_repo=mock_redis_repo)

    # Execution
    await tracker.update_from_run("run-123")

    # Verification
    assert mock_redis_repo.upsert_pattern.called


@pytest.mark.asyncio
async def test_redis_fp_repo_fallback_lru_and_memory_bounds():
    # Enforce a small fallback cache size of 3
    repo = RedisFPRepository("redis://localhost:6379/0", max_entries=3)
    # Mock redis client calls to fail so it always relies on fallback
    repo._client = AsyncMock()
    # Mock upsert to force fallback path
    repo._degraded_until = time.time() + 3600.0  # Force degraded circuit open path

    p1 = FPPattern.create(category="cat1")
    p2 = FPPattern.create(category="cat2")
    p3 = FPPattern.create(category="cat3")
    p4 = FPPattern.create(category="cat4")

    # Upsert 3 patterns
    await repo.upsert_pattern(p1)
    await repo.upsert_pattern(p2)
    await repo.upsert_pattern(p3)

    assert len(repo._fallback) == 3

    # Access p1 to move it to MRU (most recently used)
    # Mock hget to fail and fall back to cache read
    repo._client.hget.side_effect = Exception("Redis failed")
    fetched = await repo.get_pattern(p1.pattern_id)
    assert fetched is not None
    assert fetched.pattern_id == p1.pattern_id

    # Upsert p4 (should trigger eviction of p2, which is LRU because p1 was accessed)
    await repo.upsert_pattern(p4)

    assert len(repo._fallback) == 3
    assert p2.pattern_id not in repo._fallback
    assert p1.pattern_id in repo._fallback
    assert p3.pattern_id in repo._fallback
    assert p4.pattern_id in repo._fallback

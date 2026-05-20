import json
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
    mock_redis_repo.list_patterns = AsyncMock(return_value=[
        FPPattern.create(category="redis-cat", status_codes={429}, body_indicators=["rate limit"])
    ])

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
    mock_store.get_findings_for_run.return_value = [{
        "response_status": 403,
        "evidence": "Access Denied by WAF",
        "category": "xss",
        "decision": "DROP",
        "lifecycle_state": "DISCOVERED"
    }]

    tracker = FPTracker(store=mock_store, redis_repo=mock_redis_repo)

    # Execution
    await tracker.update_from_run("run-123")

    # Verification
    assert mock_redis_repo.upsert_pattern.called

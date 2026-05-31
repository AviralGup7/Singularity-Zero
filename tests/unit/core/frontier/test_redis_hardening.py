from __future__ import annotations

import pytest

from src.core.frontier.ghost_actor_registry import GhostMeshRegistry
from src.learning.models.fp_pattern import FPPattern
from src.learning.repositories.redis_fp_repo import RedisFPRepository


class _FailingAsyncRedis:
    async def hset(self, *_args, **_kwargs):
        raise TimeoutError("redis timed out")

    async def hget(self, *_args, **_kwargs):
        raise TimeoutError("redis timed out")

    async def hgetall(self, *_args, **_kwargs):
        raise TimeoutError("redis timed out")

    async def hdel(self, *_args, **_kwargs):
        raise TimeoutError("redis timed out")

    async def delete(self, *_args, **_kwargs):
        raise TimeoutError("redis timed out")

    async def expire(self, *_args, **_kwargs):
        raise TimeoutError("redis timed out")

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_redis_fp_repo_uses_local_fallback_when_redis_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "src.learning.repositories.redis_fp_repo.redis.from_url",
        lambda *_args, **_kwargs: _FailingAsyncRedis(),
    )
    monkeypatch.setattr("src.learning.repositories.redis_fp_repo.DEFAULT_REDIS_RETRIES", 0)
    monkeypatch.setattr(
        "src.learning.repositories.redis_fp_repo.DEFAULT_REDIS_TIMEOUT_SECONDS", 0.01
    )

    repo = RedisFPRepository("redis://unreachable")
    pattern = FPPattern.create("xss", status_codes={200}, body_indicators=["reflected"])

    await repo.upsert_pattern(pattern)

    assert await repo.get_pattern(pattern.pattern_id) == pattern
    assert [p.pattern_id for p in await repo.list_patterns()] == [pattern.pattern_id]

    await repo.delete_pattern(pattern.pattern_id)
    assert await repo.get_pattern(pattern.pattern_id) is None
    await repo.close()


@pytest.mark.asyncio
async def test_ghost_registry_keeps_actor_mapping_and_state_when_redis_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("src.core.frontier.ghost_actor_registry.REDIS_RETRIES", 0)
    monkeypatch.setattr("src.core.frontier.ghost_actor_registry.REDIS_TIMEOUT_SECONDS", 0.01)

    registry = GhostMeshRegistry(_FailingAsyncRedis(), run_id="redis-hardening")

    await registry.register_actor("actor-1", "node-a")
    await registry.store_actor_state("actor-1", b"packed-state")
    await registry.prepare_migration(
        actor_id="actor-1",
        migration_id="migration-1",
        source_node="node-a",
        target_node="node-b",
        state_digest="sha256:test",
    )

    assert await registry.find_actor("actor-1") == "node-a"
    assert await registry.retrieve_actor_state("actor-1") == b"packed-state"
    migration = await registry.get_migration("actor-1")
    assert migration is not None
    assert migration["status"] == "prepared"

    await registry.unregister_actor("actor-1")
    await registry.clear_actor_state("actor-1")
    await registry.clear_migration("actor-1")

    assert await registry.find_actor("actor-1") is None
    assert await registry.retrieve_actor_state("actor-1") is None
    assert await registry.get_migration("actor-1") is None

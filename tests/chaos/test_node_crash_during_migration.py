import pytest
import pykka
from typing import Any, cast
from unittest.mock import MagicMock

from src.core.frontier.ghost_actor import (
    ActorState,
    GhostMeshRegistry,
    GhostMeshCoordinator,
    ScanActor,
)


class MockRedisAsync:
    """Thread-safe mock Redis client for high-concurrency registry testing."""

    def __init__(self) -> None:
        self.data: dict[tuple[str, str], Any] = {}

    async def hset(self, key: str, field: str, value: Any) -> None:
        self.data[(key, field)] = value

    async def hget(self, key: str, field: str) -> Any:
        return self.data.get((key, field))

    async def hdel(self, key: str, field: str) -> None:
        self.data.pop((key, field), None)

    async def expire(self, key: str, seconds: int) -> None:
        pass


def mock_logic(task_input, state):
    state["status"] = "running"
    return {"status": "ok"}


@pytest.mark.asyncio
async def test_node_crash_mid_migration() -> None:
    """Chaos test: Verify registry transaction isolation prevents orphaned state during crash mid-migration."""
    redis_mock = MockRedisAsync()
    registry = GhostMeshRegistry(redis_mock, run_id="chaos-run")

    actor_id = "actor-critical"
    source_node = "node-alpha"
    target_node = "node-beta"
    migration_id = "mig-12345"

    # Start a scan actor on source node
    actor_ref = ScanActor.start(actor_id=actor_id, logic_fn=mock_logic)
    actor = actor_ref.proxy()
    actor.on_receive({"command": "execute", "input": {}}).get()

    # 1. Start migration prepare
    packed_snapshot = actor_ref.ask({"command": "prepare_migration", "migration_id": migration_id})
    assert isinstance(packed_snapshot, bytes)

    # 2. Store in registry
    await registry.store_actor_state(actor_id, packed_snapshot)
    await registry.prepare_migration(
        actor_id=actor_id,
        migration_id=migration_id,
        source_node=source_node,
        target_node=target_node,
        state_digest="digest-abc",
    )

    # 3. Simulate sudden crash of the source node (we stop actor thread abruptly without clean commit_migration)
    actor_ref.stop()

    # 4. Check migration status in registry: it must remain 'prepared'
    migration = await registry.get_migration(actor_id)
    assert migration is not None
    assert migration["status"] == "prepared"
    assert migration["source_node"] == source_node
    assert migration["target_node"] == target_node

    # 5. Verify the target node (node-beta) orchestrator can safely recover the state from the prepared migration marker
    target_coordinator = GhostMeshCoordinator(registry, MagicMock())
    
    # Target rehydrates the actor successfully
    recovered_ref = await target_coordinator.spawn_or_rehydrate_actor(actor_id, mock_logic)
    
    try:
        snapshot = recovered_ref.ask({"command": "snapshot"}, block=True)
        assert snapshot.data["status"] == "running"
        
        # Verify it cleaned up the migration state after successful recovery
        assert await registry.get_migration(actor_id) is None
        assert await registry.retrieve_actor_state(actor_id) is None
    finally:
        recovered_ref.stop()

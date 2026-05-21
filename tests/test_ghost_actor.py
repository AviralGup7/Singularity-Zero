import time
from typing import Any

import pytest

from src.core.frontier.ghost_actor import ActorState, GhostMeshRegistry, ScanActor


def mock_logic(task_input, state):
    state["last_input"] = task_input
    return {"processed": True}


def test_actor_state_packing():
    state = ActorState(
        actor_id="test-actor", stage="recon", data={"key": "value"}, checkpoint_ts=time.time()
    )
    packed = state.pack()
    assert isinstance(packed, bytes)

    unpacked = ActorState.unpack(packed)
    assert unpacked.actor_id == state.actor_id
    assert unpacked.data == state.data
    assert unpacked.checkpoint_ts == state.checkpoint_ts


def test_actor_migration_serialization():
    actor = ScanActor.start(actor_id="actor-1", logic_fn=mock_logic).proxy()

    # 1. Execute logic to set some state
    actor.on_receive({"command": "execute", "input": {"url": "example.com"}}).get()

    # 2. Trigger migration
    packed_snapshot = actor.on_receive({"command": "migrate"}).get()

    assert isinstance(packed_snapshot, bytes)

    # 3. Unpack and verify state
    snapshot = ActorState.unpack(packed_snapshot)
    assert snapshot.actor_id == "actor-1"
    assert snapshot.data["last_input"] == {"url": "example.com"}

    actor.stop()


def test_actor_recovery_from_snapshot():
    actor_id = "actor-2"
    snapshot_data = {"progress": 50, "discovered": ["a", "b"]}

    state = ActorState(
        actor_id=actor_id, stage="analysis", data=snapshot_data, checkpoint_ts=time.time()
    )
    packed = state.pack()

    # Simulate recovery on a new node
    new_actor = ScanActor.start(actor_id=actor_id, logic_fn=mock_logic).proxy()

    # Normally the coordinator or orchestrator would handle this.
    # We'll just manually set the state from the unpacked snapshot for this test
    recovered_state = ActorState.unpack(packed)
    new_actor.on_receive({"command": "recover", "deltas": [{"delta": recovered_state.data}]}).get()

    # Verify recovered state
    actual_state = new_actor.on_receive({"command": "snapshot"}).get().data
    assert actual_state["progress"] == 50
    assert actual_state["discovered"] == ["a", "b"]

    new_actor.stop()


def test_actor_recovery_deduplicates_wal_lists():
    actor = ScanActor.start(actor_id="actor-dedupe", logic_fn=mock_logic)

    try:
        deltas = [
            {"id": "1-0", "delta": {"findings": [{"id": "f1"}]}},
            {"id": "1-0", "delta": {"findings": [{"id": "f1"}]}},
            {"id": "2-0", "delta": {"findings": [{"id": "f1"}, {"id": "f2"}]}},
        ]
        result = actor.ask({"command": "recover", "deltas": deltas}, block=True)
        snapshot = actor.ask({"command": "snapshot"}, block=True)

        assert result["status"] == "success"
        assert snapshot.data["findings"] == [{"id": "f1"}, {"id": "f2"}]
        assert snapshot.last_wal_id == "2-0"
    finally:
        actor.stop()


class _AsyncRedis:
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


@pytest.mark.asyncio
async def test_registry_migration_marker_prepare_commit_clear():
    registry = GhostMeshRegistry(_AsyncRedis(), run_id="run")

    await registry.prepare_migration(
        actor_id="actor",
        migration_id="mig-1",
        source_node="node-a",
        target_node="node-b",
        state_digest="abc",
    )
    prepared = await registry.get_migration("actor")
    assert prepared is not None
    assert prepared["status"] == "prepared"

    await registry.commit_migration("actor", "mig-1")
    committed = await registry.get_migration("actor")
    assert committed is not None
    assert committed["status"] == "committed"

    await registry.clear_migration("actor")
    assert await registry.get_migration("actor") is None


def test_actor_migration_command_rejection():
    actor = ScanActor.start(actor_id="actor-migrating-test", logic_fn=mock_logic).proxy()

    # Verify commands work initially
    res1 = actor.on_receive({"command": "execute", "input": {"step": "recon"}}).get()
    assert res1["status"] == "success"

    # Set migrating to True
    actor.is_migrating = True

    # Verify execute command is blocked
    res2 = actor.on_receive({"command": "execute", "input": {"step": "exploit"}}).get()
    assert res2["status"] == "error"
    assert "currently migrating" in res2["error"]

    # Verify recover command is blocked
    res3 = actor.on_receive({"command": "recover", "deltas": []}).get()
    assert res3["status"] == "error"
    assert "currently migrating" in res3["error"]

    # Verify health_check command is NOT blocked (health check should always be readable)
    res_health = actor.on_receive({"command": "health_check"}).get()
    assert res_health["actor_id"] == "actor-migrating-test"

    # Verify migrate command is blocked when already migrating
    res_mig = actor.on_receive({"command": "migrate"}).get()
    assert res_mig["status"] == "error"
    assert "currently migrating" in res_mig["error"]

    actor.stop()

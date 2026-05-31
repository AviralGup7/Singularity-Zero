import time
from types import SimpleNamespace
from typing import Any

import pytest

from src.core.frontier.ghost_actor import ActorState, GhostMeshCoordinator, ScanActor
from src.core.frontier.ghost_actor_registry import GhostMeshRegistry


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


def test_actor_snapshot_does_not_expose_mutable_state_references():
    actor = ScanActor.start(actor_id="actor-snapshot-isolation", logic_fn=mock_logic)

    try:
        actor.ask(
            {
                "command": "recover",
                "deltas": [{"id": "1-0", "delta": {"findings": [{"id": "f1"}]}}],
            },
            block=True,
        )

        snapshot = actor.ask({"command": "snapshot"}, block=True)
        snapshot.data["findings"].append({"id": "external"})

        fresh_snapshot = actor.ask({"command": "snapshot"}, block=True)
        assert fresh_snapshot.data["findings"] == [{"id": "f1"}]
    finally:
        actor.stop()


def test_actor_execute_copies_input_and_output_across_mailbox_boundary():
    def aliasing_logic(task_input, state):
        state["task"] = task_input
        return {"task": state["task"]}

    actor = ScanActor.start(actor_id="actor-execute-isolation", logic_fn=aliasing_logic)
    caller_input = {"nested": {"items": ["owned-by-caller"]}}

    try:
        result = actor.ask({"command": "execute", "input": caller_input}, block=True)
        caller_input["nested"]["items"].append("mutated-after-execute")
        result["output"]["task"]["nested"]["items"].append("mutated-output")

        snapshot = actor.ask({"command": "snapshot"}, block=True)
        assert snapshot.data["task"] == {"nested": {"items": ["owned-by-caller"]}}
    finally:
        actor.stop()


def test_actor_recovery_copies_wal_delta_values():
    actor = ScanActor.start(actor_id="actor-recover-isolation", logic_fn=mock_logic)
    delta = {"id": "1-0", "delta": {"findings": [{"id": "f1"}]}}

    try:
        actor.ask({"command": "recover", "deltas": [delta]}, block=True)
        delta["delta"]["findings"].append({"id": "mutated-after-recover"})

        snapshot = actor.ask({"command": "snapshot"}, block=True)
        assert snapshot.data["findings"] == [{"id": "f1"}]
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


class _FailingStateRedis(_AsyncRedis):
    async def hset(self, key: str, field: str, value: Any) -> None:
        if ":state:" in key:
            raise RuntimeError("state store unavailable")
        await super().hset(key, field, value)


def _pressured_gossip() -> Any:
    return SimpleNamespace(
        local_node=SimpleNamespace(
            id="node-a",
            cpu_usage=99.0,
            ram_available_mb=100.0,
            active_jobs=0,
        ),
        peers={},
    )


@pytest.mark.asyncio
async def test_failed_migration_unfreezes_source_actor():
    registry = GhostMeshRegistry(_FailingStateRedis(), run_id="rollback")
    coordinator = GhostMeshCoordinator(registry, _pressured_gossip())
    coordinator.balancer.select_best_node_from_gossip = lambda _g, _m: "node-b"
    actor = ScanActor.start(actor_id="actor-rollback", logic_fn=mock_logic)

    try:
        migrated = await coordinator.migrate_if_needed(actor, {"actor_id": "actor-rollback"})
        assert migrated is False

        result = actor.ask({"command": "execute", "input": {"step": "after-failure"}}, block=True)
        assert result["status"] == "success"
    finally:
        if actor.is_alive():
            actor.stop()


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


def test_actor_logic_fn_serialization():
    # Define a dynamic logic function
    def dynamic_logic(task_input, state):
        state["dynamic_ran"] = True
        return {"result": task_input.get("x", 0) * 2}

    actor = ScanActor.start(actor_id="actor-dynamic", logic_fn=dynamic_logic).proxy()

    # Dehydrate actor state
    packed = actor.on_receive({"command": "dehydrate"}).get()
    assert isinstance(packed, bytes)

    # Spawn new actor and rehydrate it
    new_actor = ScanActor.start(actor_id="actor-dynamic-recovered", logic_fn=mock_logic).proxy()
    new_actor.on_receive({"command": "rehydrate", "payload": packed}).get()

    # Execute dynamic logic on the rehydrated actor to verify function was successfully pickle-transferred
    res = new_actor.on_receive({"command": "execute", "input": {"x": 21}}).get()
    assert res["status"] == "success"
    assert res["output"] == {"result": 42}

    # Check that state was updated by the dynamic logic function
    snapshot = new_actor.on_receive({"command": "snapshot"}).get()
    assert snapshot.data.get("dynamic_ran") is True

    actor.stop()
    new_actor.stop()

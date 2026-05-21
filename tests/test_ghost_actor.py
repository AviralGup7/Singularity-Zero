import time

from src.core.frontier.ghost_actor import ActorState, ScanActor


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

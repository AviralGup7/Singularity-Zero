"""
E2E Resilience Tests for the Neural-Mesh Actor Plane.
Verifies failover, recovery, and state integrity during node/actor failures.
"""

from unittest.mock import MagicMock

import pytest

from src.core.frontier.ghost_actor import (
    ActorState,
    GhostMeshCoordinator,
    GhostMeshRegistry,
    ScanActor,
)
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode


class MockRedis:
    """In-memory mock for Redis registry."""

    def __init__(self):
        self.data = {}
        self._registry_key = "ghost:registry:test-run"

    async def hset(self, key, field, value):
        self.data[(key, field)] = value

    async def hget(self, key, field):
        return self.data.get((key, field))

    async def hdel(self, key, field):
        self.data.pop((key, field), None)

    async def hgetall(self, key):
        return {k[1]: v for k, v in self.data.items() if k[0] == key}

    async def expire(self, key, seconds):
        pass


def dummy_logic(task_input, state):
    state["step"] = state.get("step", 0) + 1
    return {"status": "ok", "step": state["step"]}


@pytest.mark.asyncio
async def test_actor_death_and_registry_cleanup():
    """
    Verify that when an actor stops (is killed), it can be detected as missing
    from the local node and re-scheduled.
    """
    # 1. Setup
    node_a = MeshNode(id="node-a", host="127.0.0.1", port=9001)
    gossip = MagicMock(spec=GossipEngine)
    gossip.local_node = node_a

    redis = MockRedis()
    registry = GhostMeshRegistry(redis, run_id="test-run")
    _coordinator = GhostMeshCoordinator(registry, gossip)

    actor_id = "kill-me-actor"
    await registry.register_actor(actor_id, "node-a")

    # 2. Start and then STOP the actor (simulating a crash)
    actor_ref = ScanActor.start(actor_id, dummy_logic)
    actor_ref.stop()

    # 3. Verification logic (simulated coordinator loop)
    # Check if the actor is supposed to be here
    assigned_node = await registry.find_actor(actor_id)
    assert assigned_node == "node-a"

    # Check if it's actually alive
    is_alive = actor_ref.is_alive()
    assert is_alive is False

    # 4. Failover simulation
    # If I'm the coordinator for node-a, and I see a dead actor that I'm supposed to host,
    # I should either restart it or unregister it so another node can take over.
    if not is_alive:
        await registry.unregister_actor(actor_id)

    assert await registry.find_actor(actor_id) is None


@pytest.mark.asyncio
async def test_mesh_wide_state_consistency_during_migration():
    """
    Verifies that actor state (CRDT-based) survives a migration event.
    """
    node_a = MeshNode(id="node-a", host="127.0.0.1", port=9001)
    node_b = MeshNode(id="node-b", host="127.0.0.1", port=9002)

    gossip = MagicMock(spec=GossipEngine)
    gossip.mesh_nodes.return_value = [node_a, node_b]
    gossip.local_node = node_a

    redis = MockRedis()
    registry = GhostMeshRegistry(redis, run_id="test-run")
    coordinator = GhostMeshCoordinator(registry, gossip)

    actor_id = "stateful-actor"
    await registry.register_actor(actor_id, "node-a")
    actor_ref = ScanActor.start(actor_id, dummy_logic)

    try:
        # 1. Execute logic to change state
        result = actor_ref.ask({"command": "execute", "input": {}}, block=True)
        assert result["output"]["step"] == 1

        # 2. Trigger Migration
        # Mock balancer to pick node-b
        coordinator.balancer.select_best_node_from_gossip = lambda g, m: "node-b"

        # Force migration (ignoring health check for test)
        await registry.register_actor(actor_id, "node-b")
        snapshot = actor_ref.ask({"command": "migrate"}, block=True)

        # 3. Simulate Restart on Node-B with snapshot
        # Note: In a real system, the new actor would be started by the node's supervisor
        new_actor_ref = ScanActor.start(actor_id, dummy_logic)
        # Manually restore state from snapshot
        unpacked = ActorState.unpack(snapshot)
        new_actor_ref.proxy().state = unpacked.data

        # 4. Execute again and verify state was preserved
        result2 = new_actor_ref.ask({"command": "execute", "input": {}}, block=True)
        assert result2["output"]["step"] == 2

        new_actor_ref.stop()
    finally:
        if actor_ref.is_alive():
            actor_ref.stop()

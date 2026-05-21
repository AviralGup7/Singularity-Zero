from typing import Any, cast
from unittest.mock import MagicMock

import pykka
import pytest

from src.core.frontier.ghost_actor import (
    GhostMeshCoordinator,
    GhostMeshRegistry,
    ScanActor,
)
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode


class MockRedis:
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


def dummy_logic(task_input: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    state["processed"] = True
    return {"result": "ok"}


@pytest.mark.asyncio
async def test_proactive_migration_on_node_pressure(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Setup Mock Gossip Mesh
    node_a = MeshNode(
        id="node-a", host="127.0.0.1", port=9001, cpu_usage=95.0, ram_available_mb=100.0
    )
    node_b = MeshNode(
        id="node-b", host="127.0.0.1", port=9002, cpu_usage=10.0, ram_available_mb=8000.0
    )

    gossip = MagicMock(spec=GossipEngine)
    gossip.mesh_nodes.return_value = [node_a, node_b]
    gossip.local_node = node_a

    # 2. Mock psutil for node-a (simulating high load)
    mock_psutil = MagicMock()
    mock_psutil.cpu_percent.return_value = 95.0
    mock_psutil.virtual_memory.return_value.percent = 98.0
    monkeypatch.setattr("src.core.frontier.ghost_actor.psutil", mock_psutil)
    monkeypatch.setattr("src.infrastructure.mesh.bidder.psutil", mock_psutil)

    # 3. Setup Registry and Coordinator
    redis = MockRedis()
    registry = GhostMeshRegistry(redis, run_id="test-run")
    coordinator = GhostMeshCoordinator(registry, gossip)

    # 4. Start Actor on Node-A
    actor_id = "actor-123"
    await registry.register_actor(actor_id, "node-a")
    actor_ref = ScanActor.start(actor_id, dummy_logic)

    try:
        # Trigger health check within actor
        health = cast(dict[str, Any], actor_ref.ask({"command": "health_check"}))
        assert health["evacuation_recommended"] is True
        assert health["node_cpu"] == 95.0

        # 5. Execute Proactive Migration
        monkeypatch.setattr(
            coordinator.balancer, "select_best_node_from_gossip", lambda g, m: "node-b"
        )

        success = await coordinator.migrate_if_needed(actor_ref, {"required_capabilities": []})

        assert success is True
        assert await registry.find_actor(actor_id) == "node-b"

        # Verify actor-a is stopped (is_migrating would be true if we could check it,
        # but actor is stopped so we can't ask)
        with pytest.raises(pykka.ActorDeadError):
            actor_ref.ask({"command": "health_check"})

    finally:
        if actor_ref.is_alive():
            actor_ref.stop()


@pytest.mark.asyncio
async def test_neural_mesh_balancer_suitability_logic() -> None:
    from src.infrastructure.mesh.balancer import NeuralMeshBalancer

    balancer = NeuralMeshBalancer()

    # Node A: High load, low RAM
    node_a = {"id": "node-a", "cpu_usage": 90.0, "ram_available_mb": 100.0}
    # Node B: Low load, high RAM
    node_b = {"id": "node-b", "cpu_usage": 10.0, "ram_available_mb": 4000.0}

    score_a = balancer.calculate_node_suitability(node_a, bid=0.5)
    score_b = balancer.calculate_node_suitability(node_b, bid=0.5)

    assert score_b > score_a
    print(f"Scores: A={score_a}, B={score_b}")


@pytest.mark.asyncio
async def test_failover_node_exclusion() -> None:
    from src.infrastructure.mesh.balancer import NeuralMeshBalancer

    balancer = NeuralMeshBalancer()

    node_a = MeshNode(
        id="node-a",
        host="127.0.0.1",
        port=9001,
        status="dead",
        cpu_usage=10.0,
        ram_available_mb=8000.0,
    )
    node_b = MeshNode(
        id="node-b",
        host="127.0.0.1",
        port=9002,
        status="alive",
        cpu_usage=10.0,
        ram_available_mb=8000.0,
    )

    gossip = MagicMock(spec=GossipEngine)
    gossip.mesh_nodes.return_value = [node_a, node_b]

    # node-a is dead, so it should be excluded regardless of its good metrics
    best_node = balancer.select_best_node_from_gossip(gossip, {})
    assert best_node == "node-b"


@pytest.mark.asyncio
async def test_automatic_actor_migration_and_rehydration(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Setup Mock Gossip Mesh
    node_a = MeshNode(
        id="node-a", host="127.0.0.1", port=9001, cpu_usage=95.0, ram_available_mb=100.0
    )
    node_b = MeshNode(
        id="node-b", host="127.0.0.1", port=9002, cpu_usage=10.0, ram_available_mb=8000.0
    )

    gossip = MagicMock(spec=GossipEngine)
    gossip.mesh_nodes.return_value = [node_a, node_b]
    gossip.local_node = node_a

    # 2. Mock psutil for node-a (simulating high load to trigger migration)
    mock_psutil = MagicMock()
    mock_psutil.cpu_percent.return_value = 95.0
    mock_psutil.virtual_memory.return_value.percent = 98.0
    monkeypatch.setattr("src.core.frontier.ghost_actor.psutil", mock_psutil)

    # 3. Setup Registry and Coordinator
    redis = MockRedis()
    registry = GhostMeshRegistry(redis, run_id="test-run")
    coordinator = GhostMeshCoordinator(registry, gossip)

    # 4. Start Actor on Node-A with stateful_logic
    actor_id = "actor-state-999"
    await registry.register_actor(actor_id, "node-a")

    def stateful_logic(task_input: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        state["counter"] = state.get("counter", 0) + task_input.get("increment", 1)
        state["current_stage"] = "processing"
        return {"counter": state["counter"]}

    # Spawn/rehydrate first actor on Node-A (fresh start, but registry has no state, so it's a new spawn)
    actor_ref = await coordinator.spawn_or_rehydrate_actor(actor_id, stateful_logic)

    try:
        # Run some execution to establish state
        res1 = cast(dict[str, Any], actor_ref.ask({"command": "execute", "input": {"increment": 5}}))
        assert res1["status"] == "success"
        assert res1["output"]["counter"] == 5

        # Also health check should trigger evacuation_recommended
        health = cast(dict[str, Any], actor_ref.ask({"command": "health_check"}))
        assert health["evacuation_recommended"] is True

        # Mock the balancer to select Node-B for migration
        monkeypatch.setattr(
            coordinator.balancer, "select_best_node_from_gossip", lambda g, m: "node-b"
        )

        # 5. Migrate actor
        success = await coordinator.migrate_if_needed(actor_ref, {"actor_id": "state-999"})
        assert success is True

        # Verify first actor is dead
        with pytest.raises(pykka.ActorDeadError):
            actor_ref.ask({"command": "health_check"})

        # Verify mapping is updated to node-b
        assert await registry.find_actor(actor_id) == "node-b"

        # Verify that state is indeed in registry
        packed_state = await registry.retrieve_actor_state(actor_id)
        assert packed_state is not None

        # 6. Rehydrate on Node-B (simulated by Gossip local node changing to Node-B,
        # but spawn_or_rehydrate_actor is location-independent in coordinator)
        gossip.local_node = node_b

        # Spawn/rehydrate on Node-B
        actor_ref_b = await coordinator.spawn_or_rehydrate_actor(actor_id, stateful_logic)

        try:
            # Check state was rehydrated
            state_proxy = cast(dict[str, Any], actor_ref_b.proxy().state.get())
            assert state_proxy.get("counter") == 5
            assert state_proxy.get("current_stage") == "processing"

            # Execute another task, it should increment from 5
            res2 = cast(dict[str, Any], actor_ref_b.ask({"command": "execute", "input": {"increment": 10}}))
            assert res2["status"] == "success"
            assert res2["output"]["counter"] == 15

            # Verify that state is cleaned up from registry to save space
            assert await registry.retrieve_actor_state(actor_id) is None

        finally:
            if actor_ref_b.is_alive():
                actor_ref_b.stop()

    finally:
        if actor_ref.is_alive():
            actor_ref.stop()

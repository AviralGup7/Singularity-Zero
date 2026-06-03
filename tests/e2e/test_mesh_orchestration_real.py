import asyncio
from typing import Any, cast
from unittest.mock import MagicMock

import pykka
import pytest

from src.core.frontier.ghost_actor import (
    GhostMeshCoordinator,
    ScanActor,
)
from src.core.frontier.ghost_actor_registry import GhostMeshRegistry
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
        res1 = cast(
            dict[str, Any], actor_ref.ask({"command": "execute", "input": {"increment": 5}})
        )
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
            res2 = cast(
                dict[str, Any], actor_ref_b.ask({"command": "execute", "input": {"increment": 10}})
            )
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


@pytest.mark.asyncio
async def test_live_actor_migration_handoff_udp(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Setup Mock Gossip Mesh with real _send_reliable mock
    node_a = MeshNode(
        id="node-a", host="127.0.0.1", port=9001, cpu_usage=95.0, ram_available_mb=100.0
    )
    node_b = MeshNode(
        id="node-b", host="127.0.0.1", port=9002, cpu_usage=10.0, ram_available_mb=8000.0
    )

    gossip_sender = MagicMock(spec=GossipEngine)
    gossip_sender.mesh_nodes.return_value = [node_a, node_b]
    gossip_sender.local_node = node_a
    gossip_sender.peers = {"node-b": node_b}

    # Store sent messages to verify
    sent_reliable_calls = []

    async def mock_send_reliable(
        peer: MeshNode, message_type: str, payload: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        sent_reliable_calls.append((peer, message_type, payload))
        return True, {}

    monkeypatch.setattr(gossip_sender, "_send_reliable", mock_send_reliable, raising=False)

    # 2. Mock psutil for node-a (simulating high load to trigger migration)
    mock_psutil = MagicMock()
    mock_psutil.cpu_percent.return_value = 95.0
    mock_psutil.virtual_memory.return_value.percent = 98.0
    monkeypatch.setattr("src.core.frontier.ghost_actor.psutil", mock_psutil)

    # 3. Setup Registry and Coordinator
    redis = MockRedis()
    registry = GhostMeshRegistry(redis, run_id="test-run-udp")
    coordinator_sender = GhostMeshCoordinator(registry, gossip_sender)

    # 4. Start Actor on Node-A
    actor_id = "actor-udp-123"
    await registry.register_actor(actor_id, "node-a")

    # Define a registered stateful logic
    def udp_logic(task_input: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        state["data"] = task_input.get("val", "")
        return {"ok": True}

    actor_ref = await coordinator_sender.spawn_or_rehydrate_actor(actor_id, udp_logic)

    try:
        # Run some execution to establish state
        res = cast(
            dict[str, Any], actor_ref.ask({"command": "execute", "input": {"val": "network-state"}})
        )
        assert res["status"] == "success"

        # Mock the balancer to select Node-B for migration
        monkeypatch.setattr(
            coordinator_sender.balancer, "select_best_node_from_gossip", lambda g, m: "node-b"
        )

        # 5. Migrate actor (this should trigger reliable UDP send)
        success = await coordinator_sender.migrate_if_needed(actor_ref, {"actor_id": actor_id})
        assert success is True

        # Verify UDP send was triggered with correct arguments
        assert len(sent_reliable_calls) == 1
        peer, message_type, payload = sent_reliable_calls[0]
        assert peer.id == "node-b"
        assert message_type == "ghost_actor_spawn"
        assert payload["actor_id"] == actor_id
        assert payload["logic_fn_name"] == "udp_logic"

        # 6. Simulate receiving side (Node B)
        gossip_receiver = GossipEngine(node_b, "test-secret")
        coordinator_receiver = MagicMock(spec=GhostMeshCoordinator)

        spawned_future: asyncio.Future[tuple[str, Any]] = asyncio.Future()

        async def mock_spawn(aid: str, logic: Any) -> Any:
            spawned_future.set_result((aid, logic))
            return MagicMock()

        coordinator_receiver.spawn_or_rehydrate_actor = mock_spawn
        gossip_receiver._coordinator = coordinator_receiver

        from src.infrastructure.mesh.gossip import GossipProtocol

        protocol = GossipProtocol(gossip_receiver, secret=gossip_receiver._secret)

        from src.core.frontier.ghost_actor import _LOGIC_REGISTRY

        assert "udp_logic" in _LOGIC_REGISTRY

        envelope = {
            "body": {
                "type": "ghost_actor_spawn",
                "msg_id": "test-msg-123",
                "source": {"id": "node-a", "host": "127.0.0.1", "port": 9001, "status": "alive"},
                "payload": {"actor_id": actor_id, "logic_fn_name": "udp_logic"},
            },
            "sig": "valid-sig",
        }

        monkeypatch.setattr("src.infrastructure.mesh.gossip.protocol.verify", lambda k, d, s: True)

        import json

        raw_data = json.dumps(envelope).encode("utf-8")
        protocol.datagram_received(raw_data, ("127.0.0.1", 9001))

        aid, logic = await asyncio.wait_for(spawned_future, timeout=2.0)
        assert aid == actor_id
        assert logic == udp_logic

    finally:
        if actor_ref.is_alive():
            actor_ref.stop()

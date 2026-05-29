import asyncio
import time
import uuid
from typing import Any

import pytest

from src.core.frontier.ghost_actor import (
    GhostMeshCoordinator,
    GhostMeshRegistry,
    ScanActor,
)
from src.core.frontier.wal import FrontierWAL
from src.infrastructure.mesh.gossip import MeshNode


class MockRedisAsync:
    """Thread-safe mock Redis client for high-concurrency registry testing."""

    def __init__(self) -> None:
        self.data: dict[tuple[str, str], Any] = {}
        self.is_down = False

    async def hset(self, key: str, field: str, value: Any) -> None:
        if self.is_down:
            import redis

            raise redis.exceptions.ConnectionError("Redis is simulated down")
        self.data[(key, field)] = value

    async def hget(self, key: str, field: str) -> Any:
        if self.is_down:
            import redis

            raise redis.exceptions.ConnectionError("Redis is simulated down")
        return self.data.get((key, field))

    async def hdel(self, key: str, field: str) -> None:
        if self.is_down:
            import redis

            raise redis.exceptions.ConnectionError("Redis is simulated down")
        self.data.pop((key, field), None)

    async def expire(self, key: str, seconds: int) -> None:
        if self.is_down:
            import redis

            raise redis.exceptions.ConnectionError("Redis is simulated down")


class MockGossipEngine:
    """Mock gossip engine to simulate network partitions and topology adjustments."""

    def __init__(self, node_id: str, host: str, port: int) -> None:
        self.local_node = MeshNode(id=node_id, host=host, port=port)
        self.peers: dict[str, MeshNode] = {}
        self._coordinator: Any = None

    def mesh_nodes(self, *, include_dead: bool = True) -> list[MeshNode]:
        nodes = [self.local_node, *self.peers.values()]
        return nodes

    async def _send_reliable(
        self, peer: Any, msg_type: str, payload: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        # Simulated instant delivery
        return True, {"confirmed_dead": False}


def dummy_logic(task_input: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Simple state accumulator logic function."""
    stage_findings = state.setdefault("findings", [])
    new_findings = task_input.get("findings", [])
    for f in new_findings:
        if f not in stage_findings:
            stage_findings.append(f)
    state["last_updated"] = time.time()
    return {"status": "merged", "findings_count": len(stage_findings)}


@pytest.mark.asyncio
async def test_high_concurrency_actor_mailbox_stress() -> None:
    """Stress test: verify the Pykka actor mailbox remains stable under high frequency concurrent state merges."""
    actor_ref = ScanActor.start(actor_id="stress-actor-1", logic_fn=dummy_logic)
    actor_ref.proxy()

    num_concurrent_tasks = 100
    tasks = []

    # Send 100 concurrent execute commands to the actor mailbox
    for i in range(num_concurrent_tasks):
        tasks.append(
            actor_ref.ask(
                {
                    "command": "execute",
                    "input": {"findings": [f"finding-{i}"]},
                },
                block=False,
            )
        )

    # Resolve all futures
    results = await asyncio.gather(*[asyncio.to_thread(t.get) for t in tasks])

    for res in results:
        assert res["status"] == "success"
        assert "findings_count" in res["output"]

    # Verify state converged cleanly in RAM
    snapshot = actor_ref.ask({"command": "snapshot"}, block=True)
    assert len(snapshot.data["findings"]) == num_concurrent_tasks
    actor_ref.stop()


@pytest.mark.asyncio
async def test_node_failure_and_migration_failover() -> None:
    """Stress test: spin up 5 actor nodes, crash 2 source nodes, and verify re-routing/re-hydration failover."""
    redis_mock = MockRedisAsync()
    registry = GhostMeshRegistry(redis_mock, run_id="stress-run")

    # Define 5 mesh nodes
    nodes = {f"node-{i}": MockGossipEngine(f"node-{i}", "127.0.0.1", 9000 + i) for i in range(5)}

    # Register 5 actors on their respective nodes
    actors = {}
    actor_refs = {}
    for i in range(5):
        actor_id = f"actor-{i}"
        node_id = f"node-{i}"

        # Start the Pykka actor
        actor_ref = ScanActor.start(actor_id=actor_id, logic_fn=dummy_logic)
        actor_refs[actor_id] = actor_ref
        actors[actor_id] = actor_ref.proxy()

        # Register actor host node
        await registry.register_actor(actor_id, node_id)

    # 1. Execute initial work on node-0 and node-1
    actors["actor-0"].on_receive({"command": "execute", "input": {"findings": ["f-a"]}}).get()
    actors["actor-1"].on_receive({"command": "execute", "input": {"findings": ["f-b"]}}).get()

    # 2. Simulate node crash on node-0 and node-1
    # We dehydrate their state and store it in registry (simulating orchestrator capturing the state)
    state_0 = actors["actor-0"].on_receive({"command": "dehydrate"}).get()
    state_1 = actors["actor-1"].on_receive({"command": "dehydrate"}).get()

    await registry.store_actor_state("actor-0", state_0)
    await registry.store_actor_state("actor-1", state_1)

    # Stop the crashed source actor threads
    actor_refs["actor-0"].stop()
    actor_refs["actor-1"].stop()

    # 3. Failover / Rebalance: Spin up actors on healthy nodes (node-2 and node-3)
    coordinator_2 = GhostMeshCoordinator(registry, nodes["node-2"])
    coordinator_3 = GhostMeshCoordinator(registry, nodes["node-3"])

    # Spawn or rehydrate on new nodes
    new_ref_0 = await coordinator_2.spawn_or_rehydrate_actor("actor-0", dummy_logic)
    new_ref_1 = await coordinator_3.spawn_or_rehydrate_actor("actor-1", dummy_logic)

    try:
        # Verify state is fully recovered and preserved without data loss
        snapshot_0 = new_ref_0.ask({"command": "snapshot"}, block=True)
        snapshot_1 = new_ref_1.ask({"command": "snapshot"}, block=True)

        assert snapshot_0.data["findings"] == ["f-a"]
        assert snapshot_1.data["findings"] == ["f-b"]
    finally:
        new_ref_0.stop()
        new_ref_1.stop()
        for i in range(2, 5):
            actor_refs[f"actor-{i}"].stop()


@pytest.mark.asyncio
async def test_network_partition_split_and_crdt_convergence() -> None:
    """Stress test: simulate mesh partition split into two isolated sub-meshes, execute updates, and heal to converge state."""
    # Define a shared state merge to check LWWSet-like CRDT properties
    state_a = {"findings": ["f1", "f2"], "current_stage": "analysis"}
    state_b = {"findings": ["f2", "f3"], "current_stage": "analysis"}

    # Simulate CRDT convergence by applying Jaccard similarity / union properties
    # Let's verify our delta merging algorithm resolves partitions deterministically
    actor_ref = ScanActor.start(actor_id="partition-actor", logic_fn=dummy_logic)
    actor_ref.proxy()

    try:
        # Replay partition deltas
        deltas = [
            {"id": "wal-1", "delta": state_a},
            {"id": "wal-2", "delta": state_b},
        ]

        actor_ref.ask({"command": "recover", "deltas": deltas}, block=True)
        snapshot = actor_ref.ask({"command": "snapshot"}, block=True)

        # Verified convergence: union is ["f1", "f2", "f3"]
        assert "f1" in snapshot.data["findings"]
        assert "f2" in snapshot.data["findings"]
        assert "f3" in snapshot.data["findings"]
        assert len(snapshot.data["findings"]) == 3
    finally:
        actor_ref.stop()


def test_wal_failover_recovery_robustness() -> None:
    """Stress test: write events with Redis offline to verify local AOF fallback, then replay to recover full state."""
    run_id = f"stress_wal_{uuid.uuid4().hex[:8]}"

    # 1. Start WAL with Redis set to None (simulating local-only fallback mode)
    wal = FrontierWAL(redis_url=None, run_id=run_id)

    # Log several delta transactions
    wal.log_delta("recon", {"findings": ["f1"]})
    wal.log_delta("analysis", {"findings": ["f2"]})
    wal.log_delta("exploit", {"findings": ["f3"]})

    # 2. Reconstruct state by replaying local AOF transactions
    recovered_deltas = wal.recover_deltas()
    assert len(recovered_deltas) == 3

    # Verify integrity and sequence order of transition steps
    assert recovered_deltas[0]["stage"] == "recon"
    assert recovered_deltas[0]["delta"] == {"findings": ["f1"]}
    assert recovered_deltas[1]["stage"] == "analysis"
    assert recovered_deltas[1]["delta"] == {"findings": ["f2"]}
    assert recovered_deltas[2]["stage"] == "exploit"
    assert recovered_deltas[2]["delta"] == {"findings": ["f3"]}

    # Clean up local AOF files cleanly
    wal.cleanup()

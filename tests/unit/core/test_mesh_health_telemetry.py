from __future__ import annotations

import pytest

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.bloom_mesh import NeuralBloomMesh
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode
from src.infrastructure.mesh.sync import MeshSync
from src.infrastructure.observability.metrics import get_metrics, reset_metrics_instance


def _node(node_id: str, port: int = 9000, status: str = "alive") -> MeshNode:
    return MeshNode(id=node_id, host="127.0.0.1", port=port, status=status)


def test_gossip_health_snapshot_exposes_node_partition_and_latency_metrics() -> None:
    reset_metrics_instance()
    engine = GossipEngine(_node("node-a"), "secret")
    engine._running = True
    engine.peers["node-b"] = _node("node-b", 9001)
    engine.peers["node-c"] = _node("node-c", 9002, status="suspect")
    engine._dead_nodes["node-d"] = _node("node-d", 9003, status="dead")
    engine._gossip_sync_failures_total = 2

    stats_b = engine._stats_for("node-b")
    stats_b.last_latency_ms = 12.3
    stats_c = engine._stats_for("node-c")
    stats_c.heartbeat_misses = engine.heartbeat_fail_threshold
    engine._total_sent = 10
    engine._total_failed = 1

    health = engine.mesh_health()

    assert health["node_count"] == 4
    assert health["healthy_node_count"] == 2
    assert health["unhealthy_node_count"] == 2
    assert health["suspect_node_count"] == 1
    assert health["dead_node_count"] == 1
    assert health["gossip_sync_failures_total"] == 2
    assert health["heartbeat_misses_total"] == engine.heartbeat_fail_threshold
    assert health["partition_signal"] is True
    assert health["split_brain_signal"] is False
    assert health["avg_latency_ms"] == 12.3
    assert health["drop_rate"] == 0.1

    metrics = get_metrics()
    assert metrics.gauge("mesh_node_count").get() == 4
    assert metrics.gauge("mesh_partition_signal").get() == 1.0


@pytest.mark.asyncio
async def test_gossip_send_failure_increments_sync_failure_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_metrics_instance()
    monkeypatch.setenv("MESH_RETRY_BASE_MS", "1")
    monkeypatch.setenv("MESH_RETRY_MAX_MS", "1")
    monkeypatch.setenv("MESH_RETRY_MAX_ATTEMPTS", "1")

    engine = GossipEngine(_node("node-a"), "secret")
    peer = _node("node-b", 9001)
    engine.peers[peer.id] = peer

    class BlackholeTransport:
        def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
            return None

    engine._transport = BlackholeTransport()  # type: ignore[assignment]

    ok, _payload = await engine._send_reliable(peer, "gossip", {"mesh_data": []})

    assert ok is False
    assert engine.mesh_health()["gossip_sync_failures_total"] == 1
    assert get_metrics().counter("mesh_gossip_sync_failures_total").get() == 1.0


@pytest.mark.asyncio
async def test_mesh_sync_health_snapshot_counts_publish_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_metrics_instance()

    class FakePubSub:
        pass

    class FailingRedis:
        def pubsub(self) -> FakePubSub:
            return FakePubSub()

        async def publish(self, channel: str, message: str) -> None:
            raise RuntimeError("redis unavailable")

    monkeypatch.setattr(
        "src.infrastructure.mesh.sync.redis.from_url", lambda *a, **k: FailingRedis()
    )
    sync = MeshSync("redis://example.invalid/0", "mesh:test")

    await sync.publish({"event": "update"})
    snapshot = sync.health_snapshot()

    assert snapshot["publish_failures_total"] == 1
    assert snapshot["listen_failures_total"] == 0
    assert snapshot["last_error"] == "redis unavailable"
    assert get_metrics().counter("mesh_sync_publish_failures_total").get() == 1.0


@pytest.mark.asyncio
async def test_bloom_mesh_health_snapshot_counts_sync_and_apply_failures() -> None:
    reset_metrics_instance()
    mesh = NeuralBloomMesh(
        NeuralBloomFilter(capacity=100, error_rate=0.01),
        node_id="node-a",
        sync_interval_seconds=1.0,
    )

    class FailingRedis:
        async def publish(self, channel: str, payload: bytes) -> None:
            raise RuntimeError("publish failed")

    mesh._redis = FailingRedis()

    assert await mesh.publish_snapshot() is False
    assert await mesh.apply_snapshot(b"not-msgpack") is False

    snapshot = mesh.health_snapshot()

    assert snapshot["node_count"] == 1
    assert snapshot["stale_node_count"] == 0
    assert snapshot["sync_failures_total"] == 1
    assert snapshot["snapshot_apply_failures_total"] == 1
    assert get_metrics().counter("bloom_mesh_sync_failures_total").get() == 1.0
    assert get_metrics().counter("bloom_mesh_snapshot_apply_failures_total").get() == 1.0

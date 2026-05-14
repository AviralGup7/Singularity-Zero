"""Integration-style resilience coverage for the authenticated mesh protocol.

The production incident path uses docker compose plus tc/toxiproxy where those
tools are available. This test keeps CI portable by monkeypatching the UDP send
path to simulate packet loss and a killed node deterministically.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import pytest

from src.infrastructure.mesh.gossip import GossipEngine, MeshNode


def _node(node_id: str, port: int) -> MeshNode:
    return MeshNode(id=node_id, host="127.0.0.1", port=port)


@pytest.mark.asyncio
async def test_retry_exhaustion_marks_peer_suspect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MESH_RETRY_BASE_MS", "1")
    monkeypatch.setenv("MESH_RETRY_MAX_MS", "2")
    monkeypatch.setenv("MESH_RETRY_MAX_ATTEMPTS", "3")

    engine = GossipEngine(_node("node-a", 9010), "secret")
    peer = _node("node-b", 9020)
    engine.peers[peer.id] = peer

    class BlackholeTransport:
        def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
            return None

    engine._transport = BlackholeTransport()  # type: ignore[assignment]

    ok, payload = await engine._send_reliable(peer, "gossip", {"mesh_data": []})

    assert ok is False
    assert payload == {}
    assert engine.peers[peer.id].status == "suspect"
    assert engine.mesh_health()["peer_stats"][peer.id]["retry_count"] == 3


@pytest.mark.asyncio
async def test_three_node_cluster_detects_failure_elects_leader_and_rejoins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MESH_RETRY_BASE_MS", "1")
    monkeypatch.setenv("MESH_RETRY_MAX_MS", "2")
    monkeypatch.setenv("MESH_RETRY_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SEC", "1")
    monkeypatch.setenv("HEARTBEAT_FAIL_THRESHOLD", "2")

    engines = {
        "node-a": GossipEngine(_node("node-a", 9110), "secret"),
        "node-b": GossipEngine(_node("node-b", 9120), "secret"),
        "node-c": GossipEngine(_node("node-c", 9130), "secret"),
    }
    for engine in engines.values():
        engine._running = True
        for peer_id, peer_engine in engines.items():
            if peer_id != engine.local_node.id:
                engine.peers[peer_id] = MeshNode(**asdict(peer_engine.local_node))

    killed_nodes = {"node-b"}
    send_counter = {"total": 0, "lost": 0}

    def install_packet_loss(engine: GossipEngine) -> None:
        async def fake_send(
            peer: MeshNode,
            message_type: str,
            payload: dict[str, Any],
            *,
            mark_suspect_on_failure: bool = True,
        ) -> tuple[bool, dict[str, Any]]:
            send_counter["total"] += 1
            if peer.id in killed_nodes:
                send_counter["lost"] += 1
                return False, {}

            # Deterministic 30% packet loss for reachable peers.
            if send_counter["total"] % 10 in {3, 6, 9}:
                send_counter["lost"] += 1
                return False, {}

            if message_type == "dead_probe":
                observer = engines[peer.id]
                return True, observer._handle_dead_probe(str(payload["target_id"]))
            return True, {}

        engine._send_reliable = fake_send  # type: ignore[method-assign]

    for engine in engines.values():
        install_packet_loss(engine)

    # Both surviving nodes miss heartbeats from node-b, then ask each other
    # whether the peer is dead.
    for _ in range(engines["node-a"].heartbeat_fail_threshold):
        await engines["node-a"]._heartbeat_peer(engines["node-a"].peers["node-b"])
        await engines["node-c"]._heartbeat_peer(engines["node-c"].peers["node-b"])

    for survivor_id in ("node-a", "node-c"):
        if "node-b" in engines[survivor_id].peers:
            await engines[survivor_id]._confirm_failure("node-b")

    for survivor_id in ("node-a", "node-c"):
        health = engines[survivor_id].mesh_health()
        assert "node-b" not in engines[survivor_id].peers
        assert health["peer_count"] == 2
        assert health["leader_id"] == "node-a"

        endpoint_shape = engines[survivor_id].mesh_health()
        assert endpoint_shape["peer_count"] == 2
        assert endpoint_shape["leader_id"] == "node-a"
        assert {"avg_latency_ms", "drop_rate", "active_heartbeats"} <= endpoint_shape.keys()

    killed_nodes.clear()
    rejoining_node = asdict(engines["node-b"].local_node)
    for survivor_id in ("node-a", "node-c"):
        engines[survivor_id].update_node(rejoining_node)
        assert engines[survivor_id].peers["node-b"].status == "alive"
        assert engines[survivor_id].mesh_health()["peer_count"] == 3

    assert send_counter["lost"] / max(1, send_counter["total"]) >= 0.3

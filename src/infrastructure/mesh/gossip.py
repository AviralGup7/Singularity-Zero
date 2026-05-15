"""
Cyber Security Test Pipeline - Neural-Mesh Gossip Protocol.

Implements an authenticated SWIM-style protocol over UDP with bounded
retransmission, heartbeat failure detection, and mesh health telemetry.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets as random
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        logger.warning("Invalid %s value; using %d", name, default)
        return default


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class MeshNode:
    """Metadata for a node in the gossip mesh."""

    id: str
    host: str
    port: int
    status: str = "alive"
    cpu_usage: float = 0.0
    ram_available_mb: float = 0.0
    active_jobs: int = 0
    last_seen: float = field(default_factory=time.time)


@dataclass
class PeerHealthStats:
    """Operational counters used by mesh health and topology views."""

    sent: int = 0
    received: int = 0
    failed: int = 0
    retry_count: int = 0
    heartbeat_misses: int = 0
    last_latency_ms: float | None = None
    last_heartbeat: float | None = None
    outbound_throughput: int = 0
    inbound_throughput: int = 0


class GossipEngine:
    """
    SWIM-based peer-to-peer gossip engine with HMAC authentication.

    UDP delivery is hardened with a small ack protocol. Retries use exponential
    backoff and +/-25% jitter, capped by MESH_RETRY_MAX_MS and
    MESH_RETRY_MAX_ATTEMPTS. Heartbeat failure detection is separate from the
    periodic gossip fan-out so idle meshes still converge on failures.
    """

    def __init__(self, local_node: MeshNode, secret: str):
        self.local_node = local_node
        self.peers: dict[str, MeshNode] = {}
        self.leader_id = local_node.id
        self._udp_port = local_node.port + 1000
        self._running = False
        self._secret = secret.encode("utf-8")
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: list[asyncio.Task[Any]] = []
        self._pending_acks: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._confirming: set[str] = set()
        self._dead_nodes: dict[str, MeshNode] = {}
        self._peer_stats: dict[str, PeerHealthStats] = {}
        self._total_sent = 0
        self._total_failed = 0

        self.retry_base_ms = _env_int("MESH_RETRY_BASE_MS", 100)
        self.retry_max_ms = _env_int("MESH_RETRY_MAX_MS", 2000)
        self.retry_max_attempts = _env_int("MESH_RETRY_MAX_ATTEMPTS", 5)
        self.heartbeat_interval_sec = _env_int("HEARTBEAT_INTERVAL_SEC", 2)
        self.heartbeat_fail_threshold = _env_int("HEARTBEAT_FAIL_THRESHOLD", 3)

    def _sign(self, data: bytes) -> str:
        """Create HMAC-SHA256 signature."""
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def _verify(self, data: bytes, signature: str) -> bool:
        """Verify HMAC-SHA256 signature."""
        expected = self._sign(data)
        return hmac.compare_digest(expected, signature)

    async def start(self) -> None:
        """Start the gossip listener and fan-out loops."""
        if self._running:
            return

        self._running = True
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: GossipProtocol(self),
            local_addr=(self.local_node.host, self._udp_port),
        )
        logger.info("Neural-Mesh Gossip active on UDP %d [Authenticated]", self._udp_port)

        self._tasks = [
            asyncio.create_task(self._gossip_loop(), name="mesh-gossip-loop"),
            asyncio.create_task(self._heartbeat_loop(), name="mesh-heartbeat-loop"),
            asyncio.create_task(self._dead_node_gc_loop(), name="mesh-dead-node-gc-loop"),
        ]

    async def stop(self) -> None:
        """Stop all mesh background work and close the UDP socket."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        for future in self._pending_acks.values():
            if not future.done():
                future.cancel()
        self._pending_acks.clear()

        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def _stats_for(self, peer_id: str) -> PeerHealthStats:
        return self._peer_stats.setdefault(peer_id, PeerHealthStats())

    def _retry_interval_seconds(self, attempt: int) -> float:
        base = min(self.retry_max_ms, self.retry_base_ms * (2**attempt))
        jittered = base * random.uniform(0.75, 1.25)
        return max(0.001, jittered / 1000.0)

    def _make_envelope(self, message_type: str, payload: dict[str, Any], msg_id: str | None = None) -> bytes:
        body = {
            "type": message_type,
            "msg_id": msg_id or f"{self.local_node.id}-{uuid.uuid4().hex}",
            "source": asdict(self.local_node),
            "payload": payload,
            "sent_at": time.time(),
        }
        body_json = _canonical_json(body)
        envelope = {"body": body, "sig": self._sign(body_json)}
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    async def _send_reliable(
        self,
        peer: MeshNode,
        message_type: str,
        payload: dict[str, Any],
        *,
        mark_suspect_on_failure: bool = True,
    ) -> tuple[bool, dict[str, Any]]:
        if self._transport is None:
            return False, {}

        msg_id = f"{self.local_node.id}-{uuid.uuid4().hex}"
        data = self._make_envelope(message_type, payload, msg_id=msg_id)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending_acks[msg_id] = future
        stats = self._stats_for(peer.id)
        started = time.monotonic()

        try:
            for attempt in range(self.retry_max_attempts):
                try:
                    stats.sent += 1
                    stats.outbound_throughput += 1
                    self._total_sent += 1
                    self._transport.sendto(data, (peer.host, peer.port + 1000))
                    timeout = self._retry_interval_seconds(attempt)
                    ack_payload = await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
                    stats.retry_count = 0
                    stats.last_latency_ms = (time.monotonic() - started) * 1000.0
                    return True, ack_payload
                except TimeoutError:
                    stats.retry_count = attempt + 1
                    continue
                except Exception as exc:
                    logger.debug("Mesh send to %s failed: %s", peer.id, exc)
                    stats.retry_count = attempt + 1
                    await asyncio.sleep(self._retry_interval_seconds(attempt))

            stats.failed += 1
            self._total_failed += 1
            if mark_suspect_on_failure and peer.id in self.peers:
                self.peers[peer.id].status = "suspect"
                logger.warning("Peer '%s' marked suspect after retry exhaustion", peer.id)
            return False, {}
        finally:
            self._pending_acks.pop(msg_id, None)

    async def _send_best_effort(self, peer: MeshNode, message_type: str, payload: dict[str, Any]) -> None:
        if self._transport is None:
            return
        try:
            self._stats_for(peer.id).sent += 1
            self._stats_for(peer.id).outbound_throughput += 1
            self._total_sent += 1
            self._transport.sendto(
                self._make_envelope(message_type, payload),
                (peer.host, peer.port + 1000),
            )
        except Exception as exc:
            logger.debug("Best-effort mesh send to %s failed: %s", peer.id, exc)

    def _send_ack(self, addr: tuple[str, int], ack_for: str, payload: dict[str, Any] | None = None) -> None:
        if self._transport is None:
            return
        body_payload = {"ack_for": ack_for}
        if payload:
            body_payload.update(payload)
        try:
            self._transport.sendto(self._make_envelope("ack", body_payload), addr)
        except Exception as exc:
            logger.debug("Mesh ack send failed: %s", exc)

    async def _gossip_loop(self) -> None:
        """Periodically pick random peers and sync state with authentication."""
        while self._running:
            await asyncio.sleep(2.0)
            if not self.peers:
                continue

            peers = list(self.peers.values())
            targets = random.sample(peers, min(len(peers), 3))
            payload = {
                "leader_id": self.leader_id,
                "mesh_data": [asdict(self.local_node), *[asdict(p) for p in peers]],
            }
            await asyncio.gather(
                *[
                    self._send_reliable(target, "gossip", payload, mark_suspect_on_failure=True)
                    for target in targets
                ],
                return_exceptions=True,
            )

    async def _heartbeat_loop(self) -> None:
        """Send direct heartbeats and confirm suspected peer failures."""
        while self._running:
            await asyncio.sleep(float(self.heartbeat_interval_sec))
            peers = list(self.peers.values())
            if not peers:
                continue
            await asyncio.gather(*(self._heartbeat_peer(peer) for peer in peers), return_exceptions=True)

    async def _heartbeat_peer(self, peer: MeshNode) -> None:
        ok, _ = await self._send_reliable(
            peer,
            "heartbeat",
            {"leader_id": self.leader_id},
            mark_suspect_on_failure=False,
        )
        stats = self._stats_for(peer.id)
        if ok:
            stats.heartbeat_misses = 0
            stats.last_heartbeat = time.time()
            if peer.id in self.peers:
                self.peers[peer.id].status = "alive"
                self.peers[peer.id].last_seen = time.time()
            return

        stats.heartbeat_misses += 1
        if peer.id in self.peers:
            self.peers[peer.id].status = "suspect"
        if stats.heartbeat_misses >= self.heartbeat_fail_threshold:
            await self._confirm_failure(peer.id)

    async def _confirm_failure(self, peer_id: str) -> None:
        if peer_id in self._confirming or peer_id not in self.peers:
            return

        self._confirming.add(peer_id)
        try:
            candidate = self.peers[peer_id]
            observers = [
                peer
                for peer in self.peers.values()
                if peer.id != peer_id and peer.status in {"alive", "suspect"}
            ]
            if not observers:
                self._remove_peer(peer_id, reason="heartbeat timeout without observers")
                return

            results = await asyncio.gather(
                *[
                    self._send_reliable(
                        observer,
                        "dead_probe",
                        {"target_id": peer_id, "target": asdict(candidate)},
                        mark_suspect_on_failure=False,
                    )
                    for observer in observers
                ],
                return_exceptions=True,
            )
            confirmations = 0
            responses = 0
            for result in results:
                if isinstance(result, Exception):
                    continue
                ok, payload = result
                if not ok:
                    continue
                responses += 1
                if bool(payload.get("confirmed_dead")):
                    confirmations += 1

            quorum = max(1, (responses // 2) + 1)
            if responses == 0 or confirmations >= quorum:
                self._remove_peer(peer_id, reason="confirmed heartbeat failure")
            else:
                logger.info("Peer '%s' kept suspect after confirmation round", peer_id)
        finally:
            self._confirming.discard(peer_id)

    def _remove_peer(self, peer_id: str, *, reason: str) -> None:
        node = self.peers.pop(peer_id, None)
        if not node:
            return
        node.status = "dead"
        node.last_seen = time.time()
        self._dead_nodes[peer_id] = node
        logger.error("Node '%s' removed from mesh (%s)", peer_id, reason)
        self.elect_leader()

    async def _dead_node_gc_loop(self) -> None:
        while self._running:
            await asyncio.sleep(60.0)
            cutoff = time.time() - 300.0
            for node_id, node in list(self._dead_nodes.items()):
                if node.last_seen < cutoff:
                    del self._dead_nodes[node_id]

    def _handle_ack(self, payload: dict[str, Any]) -> None:
        ack_for = str(payload.get("ack_for", ""))
        future = self._pending_acks.get(ack_for)
        if future and not future.done():
            future.set_result(payload)

    def _handle_dead_probe(self, target_id: str) -> dict[str, Any]:
        if target_id == self.local_node.id:
            return {"confirmed_dead": False, "observer": self.local_node.id}
        if target_id in self._dead_nodes:
            return {"confirmed_dead": True, "observer": self.local_node.id}
        stats = self._peer_stats.get(target_id)
        node = self.peers.get(target_id)
        confirmed_dead = node is None or (
            node.status == "suspect"
            and stats is not None
            and stats.heartbeat_misses >= self.heartbeat_fail_threshold
        )
        return {"confirmed_dead": confirmed_dead, "observer": self.local_node.id}

    def update_node(self, node_data: dict[str, Any]) -> None:
        """Update or insert a node into the local registry."""
        node_id = str(node_data["id"])
        if node_id == self.local_node.id:
            return

        node_data = dict(node_data)
        if node_data.get("status") == "dead":
            existing = self.peers.pop(node_id, None)
            self._dead_nodes[node_id] = MeshNode(**{**node_data, "last_seen": time.time()})
            if existing and self.leader_id == node_id:
                self.elect_leader()
            return

        node_data["status"] = "alive" if node_data.get("status") == "dead" else node_data.get("status", "alive")
        existing = self.peers.get(node_id)
        if existing is None or float(node_data.get("last_seen", 0.0)) >= existing.last_seen:
            node = MeshNode(**node_data)
            node.last_seen = time.time()
            self.peers[node_id] = node
            self._dead_nodes.pop(node_id, None)
            stats = self._stats_for(node_id)
            stats.heartbeat_misses = 0
            stats.last_heartbeat = time.time()
            self.elect_leader()

    def elect_leader(self) -> str:
        """Elect a deterministic leader from live local membership."""
        candidates = [self.local_node.id, *[p.id for p in self.peers.values() if p.status == "alive"]]
        self.leader_id = sorted(candidates)[0] if candidates else self.local_node.id
        return self.leader_id

    def mesh_nodes(self, *, include_dead: bool = True) -> list[MeshNode]:
        nodes = [self.local_node, *self.peers.values()]
        if include_dead:
            nodes.extend(self._dead_nodes.values())
        return nodes

    def mesh_health(self) -> dict[str, Any]:
        """Return detailed mesh health for API and SSE consumers."""
        active_nodes = [self.local_node, *[p for p in self.peers.values() if p.status != "dead"]]
        latencies = [
            stats.last_latency_ms
            for stats in self._peer_stats.values()
            if stats.last_latency_ms is not None
        ]
        sent = max(1, self._total_sent)
        nodes = self.mesh_nodes(include_dead=True)
        edges = []
        for peer in self.peers.values():
            stats = self._stats_for(peer.id)
            edges.append(
                {
                    "source": self.local_node.id,
                    "target": peer.id,
                    "throughput": stats.outbound_throughput + stats.inbound_throughput,
                    "latency_ms": round(stats.last_latency_ms or 0.0, 2),
                    "drop_rate": round(stats.failed / max(1, stats.sent), 4),
                    "status": peer.status,
                }
            )

        return {
            "peer_count": len(active_nodes),
            "leader_id": self.leader_id,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            "drop_rate": round(self._total_failed / sent, 4),
            "active_heartbeats": self._running,
            "nodes": [asdict(node) for node in nodes],
            "edges": edges,
            "retry": {
                "base_ms": self.retry_base_ms,
                "max_ms": self.retry_max_ms,
                "max_attempts": self.retry_max_attempts,
            },
            "heartbeat": {
                "interval_sec": self.heartbeat_interval_sec,
                "fail_threshold": self.heartbeat_fail_threshold,
            },
            "peer_stats": {
                peer_id: {
                    "sent": stats.sent,
                    "received": stats.received,
                    "failed": stats.failed,
                    "retry_count": stats.retry_count,
                    "heartbeat_misses": stats.heartbeat_misses,
                    "last_latency_ms": round(stats.last_latency_ms or 0.0, 2),
                    "last_heartbeat": stats.last_heartbeat,
                    "outbound_throughput": stats.outbound_throughput,
                    "inbound_throughput": stats.inbound_throughput,
                }
                for peer_id, stats in self._peer_stats.items()
            },
        }


class GossipProtocol(asyncio.DatagramProtocol):
    """Low-level UDP packet handler with HMAC verification."""

    def __init__(self, engine: GossipEngine):
        self.engine = engine

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            envelope = json.loads(data.decode("utf-8"))
            body = envelope["body"]
            if not self.engine._verify(_canonical_json(body), envelope["sig"]):
                logger.warning("Dropped unauthorized gossip packet from %s", addr)
                return

            message_type = body.get("type")
            payload = body.get("payload", {})
            source = body.get("source")
            if isinstance(source, dict):
                self.engine.update_node(source)
                source_id = str(source.get("id", ""))
                if source_id:
                    stats = self.engine._stats_for(source_id)
                    stats.received += 1
                    stats.inbound_throughput += 1

            if message_type == "ack":
                self.engine._handle_ack(payload)
                return

            ack_payload: dict[str, Any] = {}
            if message_type == "gossip":
                for node_data in payload.get("mesh_data", []):
                    if isinstance(node_data, dict):
                        self.engine.update_node(node_data)
                leader_id = payload.get("leader_id")
                if isinstance(leader_id, str) and (
                    leader_id == self.engine.local_node.id or leader_id in self.engine.peers
                ):
                    self.engine.leader_id = leader_id
            elif message_type == "heartbeat":
                leader_id = payload.get("leader_id")
                if isinstance(leader_id, str) and (
                    leader_id == self.engine.local_node.id or leader_id in self.engine.peers
                ):
                    self.engine.leader_id = leader_id
            elif message_type == "dead_probe":
                target_id = str(payload.get("target_id", ""))
                ack_payload = self.engine._handle_dead_probe(target_id)
            else:
                # Compatibility with the original unactioned gossip body shape.
                if isinstance(body.get("source"), dict):
                    self.engine.update_node(body["source"])
                for node_data in body.get("mesh_data", []):
                    if isinstance(node_data, dict):
                        self.engine.update_node(node_data)

            msg_id = str(body.get("msg_id", ""))
            if msg_id:
                self.engine._send_ack(addr, msg_id, ack_payload)
        except Exception as exc:
            logger.debug("Dropped malformed gossip packet from %s: %s", addr, exc)

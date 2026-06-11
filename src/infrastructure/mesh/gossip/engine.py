from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import threading
import time
import uuid
from dataclasses import asdict
from types import MappingProxyType
from typing import Any

from src.infrastructure.mesh.gossip.fragmentation import (
    DEFAULT_FRAGMENT_THRESHOLD,
    Fragmenter,
    MessageDeduper,
)
from src.infrastructure.mesh.gossip.models import MeshNode, PeerHealthStats
from src.infrastructure.mesh.gossip.protocol import GossipProtocol

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        logger.warning("Invalid %s value; using %d", name, default)
        return default


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


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
        self._gossip_sync_failures_total = 0
        self._mesh_lock = threading.RLock()

        self.retry_base_ms = _env_int("MESH_RETRY_BASE_MS", 100)
        self.retry_max_ms = _env_int("MESH_RETRY_MAX_MS", 2000)
        self.retry_max_attempts = _env_int("MESH_RETRY_MAX_ATTEMPTS", 5)
        self.heartbeat_interval_sec = _env_int("HEARTBEAT_INTERVAL_SEC", 2)
        self.heartbeat_fail_threshold = _env_int("HEARTBEAT_FAIL_THRESHOLD", 3)
        # UDP hardening: fragmentation for oversized envelopes and
        # msg_id dedup for at-least-once semantics.  Per-peer rate
        # limiting lives on the receive path (see GossipProtocol).
        self._fragmenter = Fragmenter(threshold=DEFAULT_FRAGMENT_THRESHOLD)
        self._msg_deduper = MessageDeduper()
        # Imported lazily to avoid an import cycle with protocol.py.
        from src.infrastructure.mesh.gossip.fragmentation import (
            PeerRateLimiter as _PeerRateLimiter,
        )
        from src.infrastructure.mesh.gossip.fragmentation import (
            Reassembler as _Reassembler,
        )

        self._peer_rate_limiter = _PeerRateLimiter()
        self._reassembler = _Reassembler()
        self.fragmented_envelopes_total = 0
        self.fragmented_fragments_total = 0

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

        bound = False
        port_to_try = self._udp_port
        for i in range(100):
            try:
                self._transport, _ = await loop.create_datagram_endpoint(  # type: ignore[type-var]
                    lambda: GossipProtocol(
                        self,
                        secret=self._secret,
                        rate_limiter=getattr(self, "_peer_rate_limiter", None),
                        reassembler=getattr(self, "_reassembler", None),
                        deduper=self._msg_deduper,
                    ),  # type: ignore[return-value]
                    local_addr=(self.local_node.host, port_to_try),
                )
                self._udp_port = port_to_try
                self.local_node.gossip_port = port_to_try
                bound = True
                break
            except OSError as exc:
                logger.debug("Mesh UDP port %d bind failed: %s. Retrying next...", port_to_try, exc)
                port_to_try += 1

        if not bound:
            self._running = False
            raise OSError(f"Could not bind to any UDP port starting from {self._udp_port}")

        logger.info("Neural-Mesh Gossip active on UDP %d [Authenticated]", self._udp_port)

        self._tasks = [
            asyncio.create_task(self._gossip_loop(), name="mesh-gossip-loop"),
            asyncio.create_task(self._heartbeat_loop(), name="mesh-heartbeat-loop"),
            asyncio.create_task(self._dead_node_gc_loop(), name="mesh-dead-node-gc-loop"),
            asyncio.create_task(self._telemetry_loop(), name="mesh-telemetry-loop"),
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
        with self._mesh_lock:
            return self._peer_stats.setdefault(peer_id, PeerHealthStats())

    def _retry_interval_seconds(self, attempt: int) -> float:
        base = min(self.retry_max_ms, self.retry_base_ms * (2**attempt))
        jittered = base * random.uniform(0.75, 1.25)  # noqa: S311
        return max(0.001, float(jittered / 1000.0))

    def _make_envelope(
        self, message_type: str, payload: dict[str, Any], msg_id: str | None = None
    ) -> bytes:
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

    def _sendto_fragmented(self, addr: tuple[str, int], data: bytes, msg_id: str) -> None:
        """Send ``data`` to ``addr``, fragmenting if it exceeds the MTU."""
        if self._transport is None:
            return
        chunks = self._fragmenter.maybe_split(data, msg_id)
        if len(chunks) > 1:
            self.fragmented_envelopes_total += 1
            self.fragmented_fragments_total += len(chunks)
        for chunk in chunks:
            try:
                self._transport.sendto(chunk, addr)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Fragmented send to %s failed: %s", addr, exc)

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
        with self._mesh_lock:
            self._pending_acks[msg_id] = future
            stats = self._peer_stats.setdefault(peer.id, PeerHealthStats())
        started = time.monotonic()

        try:
            for attempt in range(self.retry_max_attempts):
                try:
                    with self._mesh_lock:
                        stats.sent += 1
                        stats.outbound_throughput += 1
                        self._total_sent += 1
                    peer_port = (
                        peer.gossip_port if getattr(peer, "gossip_port", 0) else (peer.port + 1000)
                    )
                    self._sendto_fragmented((peer.host, peer_port), data, msg_id)
                    timeout = self._retry_interval_seconds(attempt)
                    ack_payload = await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
                    with self._mesh_lock:
                        stats.retry_count = 0
                        stats.last_latency_ms = (time.monotonic() - started) * 1000.0
                    return True, ack_payload
                except TimeoutError:
                    with self._mesh_lock:
                        stats.retry_count = attempt + 1
                    continue
                except Exception as exc:
                    logger.debug("Mesh send to %s failed: %s", peer.id, exc)
                    with self._mesh_lock:
                        stats.retry_count = attempt + 1
                    await asyncio.sleep(self._retry_interval_seconds(attempt))

            with self._mesh_lock:
                stats.failed += 1
                self._total_failed += 1
                if message_type == "gossip":
                    self._gossip_sync_failures_total += 1
                    from src.infrastructure.observability.metrics import get_metrics

                    get_metrics().counter("mesh_gossip_sync_failures_total").inc()
            if mark_suspect_on_failure:
                with self._mesh_lock:
                    if peer.id in self.peers:
                        self.peers[peer.id].status = "suspect"
                logger.warning("Peer '%s' marked suspect after retry exhaustion", peer.id)
            return False, {}
        finally:
            with self._mesh_lock:
                self._pending_acks.pop(msg_id, None)

    async def _send_best_effort(
        self, peer: MeshNode, message_type: str, payload: dict[str, Any]
    ) -> None:
        if self._transport is None:
            return
        try:
            with self._mesh_lock:
                stats = self._peer_stats.setdefault(peer.id, PeerHealthStats())
                stats.sent += 1
                stats.outbound_throughput += 1
                self._total_sent += 1
            peer_port = peer.gossip_port if getattr(peer, "gossip_port", 0) else (peer.port + 1000)
            data = self._make_envelope(message_type, payload)
            msg_id = f"{self.local_node.id}-{uuid.uuid4().hex}"
            self._sendto_fragmented((peer.host, peer_port), data, msg_id)
        except Exception as exc:
            logger.debug("Best-effort mesh send to %s failed: %s", peer.id, exc)

    def _send_ack(
        self, addr: tuple[str, int], ack_for: str, payload: dict[str, Any] | None = None
    ) -> None:
        if self._transport is None:
            return
        body_payload = {"ack_for": ack_for}
        if payload:
            body_payload.update(payload)
        try:
            data = self._make_envelope("ack", body_payload)
            self._sendto_fragmented(addr, data, f"ack-{ack_for}")
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
            await asyncio.gather(
                *(self._heartbeat_peer(peer) for peer in peers), return_exceptions=True
            )

    async def _heartbeat_peer(self, peer: MeshNode) -> None:
        ok, _ = await self._send_reliable(
            peer,
            "heartbeat",
            {"leader_id": self.leader_id},
            mark_suspect_on_failure=False,
        )
        with self._mesh_lock:
            stats = self._peer_stats.setdefault(peer.id, PeerHealthStats())
        if ok:
            stats.heartbeat_misses = 0
            stats.last_heartbeat = time.time()
            with self._mesh_lock:
                if peer.id in self.peers:
                    self.peers[peer.id].status = "alive"
                    self.peers[peer.id].last_seen = time.time()
            return

        with self._mesh_lock:
            stats.heartbeat_misses += 1
            if peer.id in self.peers:
                self.peers[peer.id].status = "suspect"
        if stats.heartbeat_misses >= self.heartbeat_fail_threshold:
            await self._confirm_failure(peer.id)

    async def _confirm_failure(self, peer_id: str) -> None:
        with self._mesh_lock:
            already_confirming = peer_id in self._confirming
            not_in_peers = peer_id not in self.peers
        if already_confirming or not_in_peers:
            return

        with self._mesh_lock:
            candidate = self.peers.get(peer_id)
            observer_peer_ids = [
                peer.id
                for peer in self.peers.values()
                if peer.id != peer_id and peer.status in {"alive", "suspect"}
            ]
            self._confirming.add(peer_id)
        try:
            if not observer_peer_ids or candidate is None:
                with self._mesh_lock:
                    self._confirming.discard(peer_id)
                self._remove_peer(peer_id, reason="heartbeat timeout without observers/candidate")
                return

            observers = [self.peers[pid] for pid in observer_peer_ids if pid in self.peers]
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
                if isinstance(result, (Exception, BaseException)):
                    continue
                ok, payload = result
                if not ok:
                    continue
                responses += 1
                if bool(payload.get("confirmed_dead")):
                    confirmations += 1

            quorum = max(1, (responses // 2) + 1)
            if responses > 0 and confirmations >= quorum:
                self._remove_peer(peer_id, reason="confirmed heartbeat failure")
            else:
                logger.info(
                    "Peer '%s' kept suspect after confirmation round (responses=%d, confirmations=%d, quorum=%d)",
                    peer_id,
                    responses,
                    confirmations,
                    quorum,
                )
        finally:
            with self._mesh_lock:
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

    async def _telemetry_loop(self) -> None:
        """Periodically refresh local hardware telemetry."""
        try:
            import psutil
        except ImportError:
            psutil = None

        # Prime the CPU counter
        if psutil:
            psutil.cpu_percent(interval=None)

        while self._running:
            if psutil:
                try:
                    # Non-blocking CPU check
                    self.local_node.cpu_usage = psutil.cpu_percent(interval=None)

                    mem = psutil.virtual_memory()
                    self.local_node.ram_available_mb = round(mem.available / (1024 * 1024), 2)

                    # Update local seen timestamp
                    self.local_node.last_seen = time.time()
                except Exception as e:
                    logger.debug("Mesh telemetry collection failed: %s", e)

            await asyncio.sleep(5.0)

    def _handle_ack(self, payload: dict[str, Any]) -> None:
        ack_for = str(payload.get("ack_for", ""))
        with self._mesh_lock:
            future = self._pending_acks.get(ack_for)
        if future and not future.done():
            future.set_result(payload)

    def _handle_dead_probe(self, target_id: str) -> dict[str, Any]:
        if target_id == self.local_node.id:
            return {"confirmed_dead": False, "observer": self.local_node.id}
        with self._mesh_lock:
            in_dead = target_id in self._dead_nodes
            stats = self._peer_stats.get(target_id)
            node = self.peers.get(target_id)
        if in_dead:
            return {"confirmed_dead": True, "observer": self.local_node.id}
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
        should_elect = False
        if node_data.get("status") == "dead":
            with self._mesh_lock:
                existing = self.peers.pop(node_id, None)
                self._dead_nodes[node_id] = MeshNode(**{**node_data, "last_seen": time.time()})
            if existing and self.leader_id == node_id:
                should_elect = True
            if should_elect:
                self.elect_leader()
            logger.info("Peer '%s' tombstoned as dead", node_id)
            return

        node_data["status"] = (
            "alive" if node_data.get("status") == "dead" else node_data.get("status", "alive")
        )
        should_update = False
        with self._mesh_lock:
            existing = self.peers.get(node_id)
            if existing is None or float(node_data.get("last_seen", 0.0)) >= existing.last_seen:
                node = MeshNode(**node_data)
                node.last_seen = time.time()
                self.peers[node_id] = node
                self._dead_nodes.pop(node_id, None)
                stats = self._peer_stats.setdefault(node_id, PeerHealthStats())
                stats.heartbeat_misses = 0
                stats.last_heartbeat = time.time()
                should_update = True
        if should_update:
            self.elect_leader()
            logger.info("Peer '%s' resurrected and re-added to mesh", node_id)

    def elect_leader(self) -> str:
        """Elect a deterministic leader from live local membership."""
        with self._mesh_lock:
            candidates = [
                self.local_node.id,
                *[p.id for p in self.peers.values() if p.status == "alive"],
            ]
            self.leader_id = sorted(candidates)[0] if candidates else self.local_node.id
        return self.leader_id

    def register_discovered_peer(self, entry: dict[str, Any]) -> MeshNode | None:
        """Add or update a peer discovered via out-of-band channels (e.g. mDNS).

        ``entry`` is the dict produced by ``WorkerDiscovery``/``WorkerListener``
        and may include the new manifest fields (``capabilities``, ``region``,
        ``zone``, ``bandwidth_mbps``, ``capacity_weight``, ``version_vector``).
        Unknown keys are ignored and missing ones fall back to the
        ``MeshNode`` defaults so we remain backwards-compatible.
        """
        node_id = entry.get("node_id") or entry.get("name")
        if not node_id or node_id == self.local_node.id:
            return None
        addresses = entry.get("addresses") or []
        host = addresses[0] if addresses else entry.get("host", "127.0.0.1")
        try:
            port = int(entry.get("port", self.local_node.port))
        except (TypeError, ValueError):
            port = self.local_node.port
        # mDNS doesn't carry a real gossip port; assume the standard
        # ``port + 1000`` convention used by the rest of the engine.
        gossip_port = port + 1000
        version_vector_raw = entry.get("version_vector")
        version_vector: dict[str, int] = {}
        if isinstance(version_vector_raw, list):
            for token in version_vector_raw:
                if "=" in token:
                    k, v = token.split("=", 1)
                    try:
                        version_vector[k] = int(v)
                    except ValueError:
                        continue
        elif isinstance(version_vector_raw, dict):
            version_vector = {str(k): int(v) for k, v in version_vector_raw.items()}
        node = MeshNode(
            id=node_id,
            host=str(host),
            port=port,
            status="alive",
            gossip_port=gossip_port,
            capabilities=list(entry.get("capabilities") or []),
            region=str(entry.get("region", "") or ""),
            zone=str(entry.get("zone", "") or ""),
            bandwidth_mbps=int(entry.get("bandwidth_mbps", 0) or 0),
            capacity_weight=float(entry.get("capacity_weight", 1.0) or 1.0),
            version_vector=MappingProxyType(dict(version_vector))
                if version_vector
                else MappingProxyType({}),
            last_seen=time.time(),
        )
        with self._mesh_lock:
            self.peers[node_id] = node
            self._dead_nodes.pop(node_id, None)
        self.elect_leader()
        return node

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

        node_count = len(nodes)
        healthy_node_count = sum(1 for node in nodes if node.status == "alive")
        unhealthy_node_count = sum(1 for node in nodes if node.status != "alive")
        suspect_node_count = sum(1 for node in nodes if node.status == "suspect")
        dead_node_count = sum(1 for node in nodes if node.status == "dead")
        heartbeat_misses_total = sum(stats.heartbeat_misses for stats in self._peer_stats.values())
        partition_signal = unhealthy_node_count > 0
        split_brain_signal = unhealthy_node_count > healthy_node_count

        from src.infrastructure.observability.metrics import get_metrics

        metrics = get_metrics()
        metrics.gauge("mesh_node_count").set(float(node_count))
        metrics.gauge("mesh_partition_signal").set(1.0 if partition_signal else 0.0)

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
            "node_count": node_count,
            "healthy_node_count": healthy_node_count,
            "unhealthy_node_count": unhealthy_node_count,
            "suspect_node_count": suspect_node_count,
            "dead_node_count": dead_node_count,
            "gossip_sync_failures_total": getattr(self, "_gossip_sync_failures_total", 0),
            "heartbeat_misses_total": heartbeat_misses_total,
            "partition_signal": partition_signal,
            "split_brain_signal": split_brain_signal,
            "hardening": {
                "fragmented_envelopes_total": self.fragmented_envelopes_total,
                "fragmented_fragments_total": self.fragmented_fragments_total,
                "deduper": {
                    "admitted_total": self._msg_deduper.admitted_total,
                    "duplicates_total": self._msg_deduper.duplicates_total,
                    "window": self._msg_deduper._window,
                },
                "rate_limiter": {
                    "allowed_total": self._peer_rate_limiter.allowed_packets_total,
                    "dropped_total": self._peer_rate_limiter.dropped_packets_total,
                    "rate_pps": self._peer_rate_limiter._rate,
                    "burst": self._peer_rate_limiter._burst,
                },
                "reassembler": {
                    "completed_total": self._reassembler.reassembly_completed_total,
                    "timeouts_total": self._reassembler.reassembly_timeouts_total,
                    "evicted_total": self._reassembler.reassembly_evicted_total,
                },
            },
        }

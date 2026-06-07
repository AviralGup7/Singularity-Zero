"""
Low-level UDP packet handler / protocol adapter for the gossip mesh.

GossipProtocol is an asyncio.DatagramProtocol subclass that authenticates
incoming packets, floods received node updates into the engine, and
dispatches typed messages to the appropriate engine callback.

Hardening (DoS protection):

* Per-peer token-bucket rate limiter (``PeerRateLimiter``) drops
  packets from peers that exceed a configurable pps budget.
* ``MessageDeduper`` discards replays by ``msg_id``.
* ``Reassembler`` joins fragmented envelopes before they hit the
  authentication step, so the signature is verified on the
  reconstructed payload.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from src.infrastructure.mesh.gossip.fragmentation import (
    MessageDeduper,
    PeerRateLimiter,
    Reassembler,
)
from src.infrastructure.mesh.gossip.serializer import canonical_json, verify

logger = logging.getLogger(__name__)


class GossipProtocol:
    """Low-level UDP packet handler with HMAC verification."""

    def __init__(
        self,
        engine: Any,
        *,
        secret: bytes,
        rate_limiter: PeerRateLimiter | None = None,
        reassembler: Reassembler | None = None,
        deduper: MessageDeduper | None = None,
    ) -> None:
        self.engine = engine
        self._secret = secret
        self.transport: asyncio.BaseTransport | None = None
        self._rate_limiter = rate_limiter or PeerRateLimiter()
        self._reassembler = reassembler or Reassembler()
        self._deduper = deduper or MessageDeduper()

    @property
    def rate_limiter(self) -> PeerRateLimiter:
        return self._rate_limiter

    @property
    def reassembler(self) -> Reassembler:
        return self._reassembler

    @property
    def deduper(self) -> MessageDeduper:
        return self._deduper

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(
        self, data: bytes, addr: tuple[str, int]
    ) -> None:  # addr: tuple[str, int]
        peer_key = f"{addr[0]}:{addr[1]}"
        if not self._rate_limiter.allow(peer_key):
            try:
                _inc_metric(
                    "dropped_gossip_packets_rate_total",
                    "Total gossip packets dropped due to per-peer rate limit",
                )
            except (OSError, ValueError, TypeError, AttributeError):
                pass
            return

        try:
            envelope = json.loads(data.decode("utf-8"))
        except Exception as exc:
            logger.warning("Dropped malformed gossip packet from %s: %s", addr, exc)
            try:
                _inc_metric(
                    "dropped_gossip_packets_total",
                    "Total dropped gossip packets due to format errors",
                )
            except (OSError, ValueError, TypeError, AttributeError) as metric_exc:
                logger.debug("Gossip metric increment failed: %s", metric_exc)
            return

        # Fragmented envelopes must be reassembled *before* signature
        # verification because the signature covers the original
        # envelope bytes, not the fragment wrapper.
        if isinstance(envelope, dict) and envelope.get("kind") == "fragment":
            raw = self._reassembler.ingest(envelope)
            if raw is None:
                return  # waiting on more fragments
            try:
                envelope = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                logger.warning("Dropped reassembled envelope from %s: %s", addr, exc)
                return

        try:
            body = envelope["body"]
            if not verify(self._secret, canonical_json(body), envelope["sig"]):
                logger.warning("Dropped unauthorized gossip packet from %s", addr)
                return
        except Exception as exc:
            logger.warning("Dropped malformed gossip packet from %s: %s", addr, exc)
            try:
                _inc_metric(
                    "dropped_gossip_packets_total",
                    "Total dropped gossip packets due to format errors",
                )
            except (OSError, ValueError, TypeError, AttributeError) as metric_exc:
                logger.debug("Gossip metric increment failed: %s", metric_exc)
            return

        msg_id = str(body.get("msg_id", ""))
        if msg_id and not self._deduper.seen(msg_id):
            try:
                _inc_metric(
                    "dropped_gossip_packets_duplicate_total",
                    "Total gossip packets dropped as duplicate msg_id",
                )
            except (OSError, ValueError, TypeError, AttributeError):
                pass
            return

        try:
            self._handle_authenticated(body, addr)
        except Exception as exc:
            logger.error(
                "Error processing authenticated gossip message from %s: %s",
                addr,
                exc,
                exc_info=True,
            )

    def _handle_authenticated(self, body: dict[str, Any], addr: tuple[str, int]) -> None:
        message_type = body.get("type")
        payload = body.get("payload", {})
        source = body.get("source")
        if isinstance(source, dict):
            self.engine.update_node(source)
            source_id = str(source.get("id", ""))
            if source_id and hasattr(self.engine, "_stats_for"):
                stats = self.engine._stats_for(source_id)
                stats.received += 1
                stats.inbound_throughput += 1

        ack_payload: dict[str, Any] = {}
        if message_type == "ack":
            self.engine._handle_ack(payload)
        elif message_type == "gossip":
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
        elif message_type == "ghost_actor_spawn":
            actor_id = payload.get("actor_id")
            logic_fn_name = payload.get("logic_fn_name")
            coordinator = getattr(self.engine, "_coordinator", None)
            if coordinator and actor_id and logic_fn_name:
                from src.core.frontier.ghost_actor import _LOGIC_REGISTRY

                logic_fn = _LOGIC_REGISTRY.get(logic_fn_name)
                if not logic_fn:

                    def dummy_logic(task_input: dict[str, Any], state: dict[str, Any]) -> Any:
                        return {}

                    dummy_logic.__name__ = str(logic_fn_name)
                    logic_fn = dummy_logic

                import asyncio

                asyncio.create_task(coordinator.spawn_or_rehydrate_actor(actor_id, logic_fn))
        else:
            if isinstance(body.get("source"), dict):
                self.engine.update_node(body["source"])
            for node_data in body.get("mesh_data", []):
                if isinstance(node_data, dict):
                    self.engine.update_node(node_data)

        msg_id = str(body.get("msg_id", ""))
        if msg_id:
            self.engine._send_ack(addr, msg_id, ack_payload)


def _inc_metric(name: str, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().counter(name, description).inc()
    except (ImportError, AttributeError, ValueError, OSError) as exc:
        logger.debug("Metrics counter increment failed for %s: %s", name, exc)

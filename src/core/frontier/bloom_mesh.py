"""Redis-backed Bloom filter reconciliation for the frontier mesh."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import msgspec

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.state import LWWset, VectorClock

logger = logging.getLogger(__name__)

BLOOM_REDIS_CHANNEL = "cyber-pipeline:bloom:sync"
DEFAULT_SYNC_INTERVAL_SECONDS = 15.0


@dataclass
class BloomNodeHealth:
    """Observable Bloom status for one mesh node."""

    node_id: str
    memory_mb: float
    element_count: int
    false_positive_probability: float
    fill_ratio: float
    last_sync_time: float
    capacity: int
    hash_count: int
    clock: dict[str, int] = field(default_factory=dict)
    stale: bool = False


class BloomMeshSynchronizer:
    """Synchronize Bloom snapshots across nodes using Redis pub/sub."""

    def __init__(
        self,
        bloom_filter: NeuralBloomFilter,
        *,
        node_id: str,
        redis_url: str | None = None,
        sync_interval_seconds: float | None = None,
        channel: str = BLOOM_REDIS_CHANNEL,
    ) -> None:
        self.filter = bloom_filter
        self.node_id = node_id
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.sync_interval_seconds = float(
            sync_interval_seconds
            if sync_interval_seconds is not None
            else os.getenv("BLOOM_SYNC_INTERVAL_SEC", DEFAULT_SYNC_INTERVAL_SECONDS)
        )
        self.channel = channel
        self.clock = VectorClock({node_id: 0})
        self.snapshot_index: LWWset[str] = LWWset()
        self.remote_clocks: dict[str, VectorClock] = {}
        self.remote_health: dict[str, BloomNodeHealth] = {}
        self.saturation_history: list[dict[str, float]] = []
        self._redis: Any = None
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False
        self._last_sync_time = 0.0

    async def start(self) -> None:
        """Start background pub/sub if Redis is configured."""
        if self._running:
            return
        self._running = True
        self._record_saturation()

        if not self.redis_url:
            logger.info("Bloom mesh Redis sync disabled; no Redis URL configured")
            return

        try:
            import redis.asyncio as redis

            self._redis = redis.from_url(self.redis_url, decode_responses=False)
            await self._redis.ping()
        except Exception as exc:
            logger.warning("Bloom mesh Redis initialization failed: %s", exc)
            self._redis = None
            return

        self._tasks = [
            asyncio.create_task(self._publish_loop(), name="bloom-mesh-publisher"),
            asyncio.create_task(self._subscribe_loop(), name="bloom-mesh-subscriber"),
        ]

    async def stop(self) -> None:
        """Stop background tasks and close Redis resources."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def force_reconcile(self) -> dict[str, Any]:
        """Publish an immediate snapshot to all online nodes."""
        published = await self.publish_snapshot(reason="manual_reconcile")
        return {
            "status": "published" if published else "local_only",
            "node_id": self.node_id,
            "redis_enabled": self._redis is not None,
            "channel": self.channel,
            "remote_nodes": len(self.remote_health),
            "last_sync_time": self._last_sync_time,
        }

    async def publish_snapshot(self, *, reason: str = "gossip") -> bool:
        """Serialize and publish the local filter snapshot."""
        now = time.time()
        self.clock = self.clock.increment(self.node_id)
        self.snapshot_index.add(self.node_id, timestamp=now, vclock=self.clock)
        self._last_sync_time = now
        self._record_saturation()

        if self._redis is None:
            return False

        payload = self._encode_snapshot(reason=reason, timestamp=now)
        await self._redis.publish(self.channel, payload)
        return True

    async def apply_snapshot(self, payload: bytes) -> bool:
        """Apply a remote snapshot when its vector clock is newer."""
        data = msgspec.msgpack.decode(payload)
        node_id = str(data["node_id"])
        if node_id == self.node_id:
            return False

        remote_clock = VectorClock(dict(data.get("vclock", {})))
        existing_clock = self.remote_clocks.get(node_id, VectorClock())
        if not remote_clock.is_later_than(existing_clock):
            return False

        if int(data["bit_size"]) != self.filter.bit_size or int(data["hash_count"]) != self.filter.hash_count:
            logger.warning("Ignoring incompatible Bloom snapshot from %s", node_id)
            return False

        remote_bits = self.filter.load_snapshot_bytes(data["bits"])
        self.filter.merge_bits(remote_bits, element_count=int(data.get("element_count", 0)))
        self.remote_clocks[node_id] = remote_clock
        self.clock = self.clock.merge(remote_clock)
        self.snapshot_index.add(node_id, timestamp=float(data["timestamp"]), vclock=remote_clock)
        self.remote_health[node_id] = BloomNodeHealth(
            node_id=node_id,
            memory_mb=float(data["stats"].get("memory_mb", 0.0)),
            element_count=int(data.get("element_count", 0)),
            false_positive_probability=float(data["stats"].get("false_positive_probability", 0.0)),
            fill_ratio=float(data["stats"].get("fill_ratio", 0.0)),
            last_sync_time=float(data["timestamp"]),
            capacity=int(data["capacity"]),
            hash_count=int(data["hash_count"]),
            clock=remote_clock.versions,
            stale=False,
        )
        self._record_saturation()
        return True

    def health_snapshot(self) -> dict[str, Any]:
        """Return local and remote health data for dashboard clients."""
        now = time.time()
        stats = self.filter.get_stats()
        local = BloomNodeHealth(
            node_id=self.node_id,
            memory_mb=float(stats["memory_mb"]),
            element_count=int(stats["element_count"]),
            false_positive_probability=float(stats["false_positive_probability"]),
            fill_ratio=float(stats["fill_ratio"]),
            last_sync_time=self._last_sync_time,
            capacity=int(stats["capacity"]),
            hash_count=int(stats["hash_count"]),
            clock=self.clock.versions,
            stale=False,
        )
        nodes = [local, *self.remote_health.values()]
        stale_after = self.sync_interval_seconds * 3
        return {
            "nodes": [
                {
                    **node.__dict__,
                    "stale": bool(node.last_sync_time and now - node.last_sync_time > stale_after),
                }
                for node in nodes
            ],
            "saturation_history": self.saturation_history[-60:],
            "sync_interval_seconds": self.sync_interval_seconds,
            "redis_enabled": self._redis is not None,
            "channel": self.channel,
        }

    def _encode_snapshot(self, *, reason: str, timestamp: float) -> bytes:
        stats = self.filter.get_stats()
        return msgspec.msgpack.encode(
            {
                "schema": 1,
                "reason": reason,
                "node_id": self.node_id,
                "timestamp": timestamp,
                "capacity": self.filter.capacity,
                "error_rate": self.filter.error_rate,
                "bit_size": self.filter.bit_size,
                "hash_count": self.filter.hash_count,
                "element_count": self.filter.element_count,
                "vclock": self.clock.versions,
                "stats": stats,
                "bits": self.filter.snapshot_bytes(),
            }
        )

    async def _publish_loop(self) -> None:
        while self._running:
            try:
                await self.publish_snapshot()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Bloom snapshot publish failed: %s", exc)
            await asyncio.sleep(self.sync_interval_seconds)

    async def _subscribe_loop(self) -> None:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(self.channel)
        try:
            while self._running:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if not message:
                    continue
                data = message.get("data")
                if isinstance(data, bytes):
                    await self.apply_snapshot(data)
        finally:
            await pubsub.unsubscribe(self.channel)
            await pubsub.aclose()

    def _record_saturation(self) -> None:
        stats = self.filter.get_stats()
        self.saturation_history.append(
            {
                "time": time.time(),
                "fill_ratio": float(stats["fill_ratio"]),
                "false_positive_probability": float(stats["false_positive_probability"]),
            }
        )
        del self.saturation_history[:-120]

"""Redis-backed Bloom filter reconciliation for the frontier mesh."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

import msgspec

from src.core.contracts.health import HealthComponent, HealthMetric, HealthStatus
from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.state import LWWset, VectorClock
from src.infrastructure.queue.redis_config import (
    REDIS_RECONNECT_SECONDS,
    REDIS_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)

BLOOM_REDIS_CHANNEL = "cyber-pipeline:bloom:sync"
DEFAULT_SYNC_INTERVAL_SECONDS = 15.0
REDIS_MAX_FAILURES = 3
INTERVAL_PARSE_ERRORS = (TypeError, ValueError)
SNAPSHOT_VALIDATION_ERRORS = (KeyError, TypeError, ValueError)
# Bump when the on-wire snapshot format is breaking; ``_encode_snapshot``
# always emits ``BLOOM_SNAPSHOT_SCHEMA`` and ``apply_snapshot`` drops
# payloads outside ``[BLOOM_SNAPSHOT_MIN_ACCEPTED, BLOOM_SNAPSHOT_MAX_ACCEPTED]``
# so a rolling upgrade can never poison receivers with an unknown shape.
BLOOM_SNAPSHOT_SCHEMA = 1
BLOOM_SNAPSHOT_MIN_ACCEPTED = 1
BLOOM_SNAPSHOT_MAX_ACCEPTED = 1
BLOOM_SNAPSHOT_IDEMPOTENCY_CACHE = 2048


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


class NeuralBloomMesh:
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
        self.sync_interval_seconds = self._resolve_sync_interval(sync_interval_seconds)
        self.channel = channel
        self.clock = VectorClock(MappingProxyType({node_id: 0}))
        self.snapshot_index: LWWset[str] = LWWset()
        self.remote_clocks: dict[str, VectorClock] = {}
        self.remote_health: dict[str, BloomNodeHealth] = {}
        self.saturation_history: list[dict[str, float]] = []
        self._redis: Any = None
        self._tasks: list[asyncio.Task[Any]] = []
        self._running = False
        self._last_sync_time = 0.0
        self._sync_failures_total = 0
        self._snapshot_apply_failures_total = 0
        self._sync_lock = asyncio.Lock()
        self._redis_failures = 0
        self._redis_degraded_until = 0.0
        self._snapshot_schema_rejected_total = 0
        self._snapshot_duplicates_dropped_total = 0
        self._idempotency_cache: OrderedDict[str, float] = OrderedDict()
        self._idempotency_lock = threading.RLock()
        self._idempotency_max = BLOOM_SNAPSHOT_IDEMPOTENCY_CACHE

    @staticmethod
    def _resolve_sync_interval(sync_interval_seconds: float | None) -> float:
        raw_value = (
            sync_interval_seconds
            if sync_interval_seconds is not None
            else os.getenv("BLOOM_SYNC_INTERVAL_SEC", DEFAULT_SYNC_INTERVAL_SECONDS)
        )
        try:
            interval = float(raw_value)
        except INTERVAL_PARSE_ERRORS:
            logger.warning(
                "Invalid BLOOM_SYNC_INTERVAL_SEC=%r; using default %.1fs",
                raw_value,
                DEFAULT_SYNC_INTERVAL_SECONDS,
            )
            return DEFAULT_SYNC_INTERVAL_SECONDS
        if interval <= 0:
            logger.warning(
                "Non-positive BLOOM_SYNC_INTERVAL_SEC=%r; using default %.1fs",
                raw_value,
                DEFAULT_SYNC_INTERVAL_SECONDS,
            )
            return DEFAULT_SYNC_INTERVAL_SECONDS
        return interval

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

            self._redis = redis.from_url(
                self.redis_url,
                decode_responses=False,
                socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
                socket_timeout=REDIS_TIMEOUT_SECONDS,
                health_check_interval=30,
                max_connections=10,
                retry_on_timeout=True,
            )
            await asyncio.wait_for(self._redis.ping(), timeout=REDIS_TIMEOUT_SECONDS)
        except Exception as exc:
            logger.warning("Bloom mesh Redis initialization failed: %s", exc)
            await self._close_redis()
            self._running = False
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
        await self._close_redis()

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

    async def flush_overflowing_filter(self, *, reason: str = "self_healing") -> dict[str, Any]:
        """Clear a saturated local filter and publish a fresh empty snapshot."""
        async with self._sync_lock:
            before = self.filter.get_stats()
            self.filter.reset()
            self.remote_health.clear()
            self.remote_clocks.clear()
            self.saturation_history.clear()
        self._record_saturation()
        published = await self.publish_snapshot(reason=reason)
        return {
            "status": "flushed",
            "node_id": self.node_id,
            "published": published,
            "before": before,
            "after": self.filter.get_stats(),
        }

    def health_metrics(self, *, fill_threshold: float = 0.92) -> list[HealthMetric]:
        """Return mesh node saturation and staleness metrics."""
        snapshot = self.health_snapshot()
        metrics: list[HealthMetric] = []
        for node in snapshot["nodes"]:
            fill_ratio = float(node.get("fill_ratio", 0.0) or 0.0)
            metrics.append(
                HealthMetric(
                    component=HealthComponent.BLOOM_MESH,
                    name="bloom_fill_ratio",
                    value=fill_ratio,
                    threshold=fill_threshold,
                    status=HealthStatus.CRITICAL
                    if fill_ratio >= fill_threshold or node.get("stale")
                    else HealthStatus.OK,
                    labels={"node_id": node.get("node_id"), "stale": bool(node.get("stale"))},
                )
            )
        return metrics

    async def publish_snapshot(self, *, reason: str = "gossip") -> bool:
        """Serialize and publish the local filter snapshot."""
        async with self._sync_lock:
            now = time.time()

            # Optimization: Only publish if element count has changed significantly
            # or if it's a forced/self-healing reason.
            stats = self.filter.get_stats()
            current_count = int(stats["element_count"])
            last_count = getattr(self, "_last_published_count", 0)

            if reason == "gossip" and current_count > 0:
                # If less than 5% change and not too old, skip
                if (current_count - last_count) < (self.filter.capacity * 0.05) and (
                    now - self._last_sync_time
                ) < (self.sync_interval_seconds * 4):
                    return False

            self.clock = self.clock.increment(self.node_id)
            self.snapshot_index.add(self.node_id, timestamp=now, vclock=self.clock)
            self._last_sync_time = now
            self._last_published_count = current_count
            self._record_saturation()

            # Prune stale nodes from remote_health to prevent memory leak
            stale_threshold = now - (self.sync_interval_seconds * 10)
            to_prune = [
                nid
                for nid, health in self.remote_health.items()
                if health.last_sync_time < stale_threshold
            ]
            for nid in to_prune:
                self.remote_health.pop(nid, None)
                self.remote_clocks.pop(nid, None)

            if self._redis is None:
                return False

            payload = self._encode_snapshot(reason=reason, timestamp=now)
        try:
            await asyncio.wait_for(
                self._redis.publish(self.channel, payload),
                timeout=REDIS_TIMEOUT_SECONDS,
            )
            self._record_redis_success()
        except Exception as exc:
            self._sync_failures_total += 1
            _inc_metric(
                "bloom_mesh_sync_failures_total",
                "Total Bloom mesh snapshot publish failures",
            )
            await self._record_redis_failure("publish", exc)
            return False
        return True

    async def apply_snapshot(self, payload: bytes) -> bool:
        """Apply a remote snapshot when its vector clock is newer.

        Snapshots are rejected up-front if their ``schema`` field falls
        outside ``[BLOOM_SNAPSHOT_MIN_ACCEPTED, BLOOM_SNAPSHOT_MAX_ACCEPTED]``
        and a content-hash idempotency window suppresses identical
        re-broadcasts (which can otherwise re-trigger expensive bitwise
        merges).
        """
        try:
            data = msgspec.msgpack.decode(payload)
            if not isinstance(data, dict):
                raise ValueError("Bloom snapshot must decode to a mapping")
        except Exception as exc:
            self._snapshot_apply_failures_total += 1
            _inc_metric(
                "bloom_mesh_snapshot_apply_failures_total",
                "Total Bloom mesh snapshot apply failures",
            )
            logger.warning("Ignoring malformed Bloom snapshot: %s", exc)
            return False

        schema_raw = data.get("schema")
        try:
            schema_int = int(schema_raw)
        except (TypeError, ValueError):
            schema_int = -1
        if not (BLOOM_SNAPSHOT_MIN_ACCEPTED <= schema_int <= BLOOM_SNAPSHOT_MAX_ACCEPTED):
            self._snapshot_schema_rejected_total += 1
            _inc_metric(
                "bloom_mesh_snapshot_schema_rejected_total",
                "Total Bloom mesh snapshots rejected for unsupported schema",
            )
            logger.warning("Ignoring Bloom snapshot with unsupported schema=%r", schema_raw)
            return False

        # Idempotency: drop replays of the same on-wire payload (e.g.
        # the publisher fan-out or a Redis-cluster echo).
        idem_key = hashlib.sha256(payload).hexdigest()
        if self._observe_idempotency(idem_key):
            self._snapshot_duplicates_dropped_total += 1
            _inc_metric(
                "bloom_mesh_snapshot_duplicates_dropped_total",
                "Total Bloom mesh snapshot replays dropped",
            )
            return False

        async with self._sync_lock:
            try:
                node_id = str(data["node_id"])
                if node_id == self.node_id:
                    return False

                remote_clock = VectorClock(MappingProxyType(dict(data.get("vclock", {}))))
                existing_clock = self.remote_clocks.get(node_id, VectorClock())
                if not remote_clock.is_later_than(existing_clock):
                    return False

                if (
                    int(data["bit_size"]) != self.filter.bit_size
                    or int(data["hash_count"]) != self.filter.hash_count
                ):
                    logger.warning("Ignoring incompatible Bloom snapshot from %s", node_id)
                    self._snapshot_apply_failures_total += 1
                    _inc_metric(
                        "bloom_mesh_snapshot_apply_failures_total",
                        "Total Bloom mesh snapshot apply failures",
                    )
                    return False

                remote_bits = self.filter.decode_snapshot_bytes(data["bits"])
                remote_count = int(data.get("element_count", 0))
                previous_remote = self.remote_health.get(node_id)
                previous_count = previous_remote.element_count if previous_remote else 0

                # Fix: Offload bitwise OR merge to thread if bits are large (>100KB)
                if len(remote_bits) > 100000:
                    await asyncio.to_thread(
                        self.filter.merge_bits,
                        remote_bits,
                        element_count=remote_count,
                        added_count=max(0, remote_count - previous_count),
                    )
                else:
                    self.filter.merge_bits(
                        remote_bits,
                        element_count=remote_count,
                        added_count=max(0, remote_count - previous_count),
                    )
                self.remote_clocks[node_id] = remote_clock
                self.clock = self.clock.merge(remote_clock)
                self.snapshot_index.add(
                    node_id, timestamp=float(data["timestamp"]), vclock=remote_clock
                )
                self.remote_health[node_id] = BloomNodeHealth(
                    node_id=node_id,
                    memory_mb=float(data["stats"].get("memory_mb", 0.0)),
                    element_count=remote_count,
                    false_positive_probability=float(
                        data["stats"].get("false_positive_probability", 0.0)
                    ),
                    fill_ratio=float(data["stats"].get("fill_ratio", 0.0)),
                    last_sync_time=float(data["timestamp"]),
                    capacity=int(data["capacity"]),
                    hash_count=int(data["hash_count"]),
                    clock=dict(remote_clock.versions),
                    stale=False,
                )
            except SNAPSHOT_VALIDATION_ERRORS as exc:
                logger.warning("Ignoring invalid Bloom snapshot: %s", exc)
                self._snapshot_apply_failures_total += 1
                _inc_metric(
                    "bloom_mesh_snapshot_apply_failures_total",
                    "Total Bloom mesh snapshot apply failures",
                )
                return False
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
            clock=dict(self.clock.versions),
            stale=False,
        )
        nodes = [local, *self.remote_health.values()]
        stale_after = self.sync_interval_seconds * 3
        node_dicts = [
            {
                **node.__dict__,
                "stale": bool(node.last_sync_time and now - node.last_sync_time > stale_after),
            }
            for node in nodes
        ]
        stale_node_count = sum(1 for node in node_dicts if node["stale"])
        _set_metric("bloom_mesh_node_count", len(node_dicts), "Total Bloom mesh nodes")
        _set_metric("bloom_mesh_stale_node_count", stale_node_count, "Stale Bloom mesh nodes")
        _set_metric(
            "bloom_mesh_sync_failures",
            self._sync_failures_total,
            "Current Bloom mesh sync failures",
        )
        _set_metric(
            "bloom_mesh_snapshot_apply_failures",
            self._snapshot_apply_failures_total,
            "Current Bloom mesh snapshot apply failures",
        )
        return {
            "nodes": node_dicts,
            "node_count": len(node_dicts),
            "stale_node_count": stale_node_count,
            "sync_failures_total": self._sync_failures_total,
            "snapshot_apply_failures_total": self._snapshot_apply_failures_total,
            "last_sync_age_seconds": round(now - self._last_sync_time, 3)
            if self._last_sync_time
            else None,
            "saturation_history": self.saturation_history[-60:],
            "sync_interval_seconds": self.sync_interval_seconds,
            "redis_enabled": self._redis is not None,
            "channel": self.channel,
        }

    def _encode_snapshot(self, *, reason: str, timestamp: float) -> bytes:
        bits, stats = self.filter.snapshot_payload()
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
                "element_count": int(stats["element_count"]),
                "vclock": dict(self.clock.versions),
                "stats": stats,
                "bits": bits,
            }
        )

    async def _publish_loop(self) -> None:
        while self._running:
            try:
                await self._ensure_redis()
                await self.publish_snapshot()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Bloom snapshot publish failed: %s", exc)
            await asyncio.sleep(self.sync_interval_seconds)

    async def _subscribe_loop(self) -> None:
        while self._running:
            pubsub = None
            try:
                await self._ensure_redis()
                if self._redis is None:
                    await asyncio.sleep(min(self.sync_interval_seconds, 5.0))
                    continue
                pubsub = self._redis.pubsub()
                await asyncio.wait_for(
                    pubsub.subscribe(self.channel), timeout=REDIS_TIMEOUT_SECONDS
                )
                while self._running:
                    message = await asyncio.wait_for(
                        pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                        timeout=REDIS_TIMEOUT_SECONDS,
                    )
                    if not message:
                        continue
                    data = message.get("data")
                    if isinstance(data, bytes):
                        try:
                            await self.apply_snapshot(data)
                            self._record_redis_success()
                        except Exception as exc:
                            logger.debug("Bloom snapshot apply failed: %s", exc)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._record_redis_failure("subscribe", exc)
                await asyncio.sleep(min(self.sync_interval_seconds, 5.0))
            finally:
                if pubsub is not None:
                    try:
                        # Fix: Always aclose pubsub to prevent connection leaks
                        await pubsub.aclose()
                    except Exception as exc:
                        logger.debug("Bloom mesh pubsub close failed: %s", exc)

    def _observe_idempotency(self, key: str) -> bool:
        """Return ``True`` if the snapshot ``key`` was already seen recently."""
        with self._idempotency_lock:
            seen = key in self._idempotency_cache
            self._idempotency_cache[key] = time.time()
            if not seen and len(self._idempotency_cache) > self._idempotency_max:
                # Evict the oldest entry.
                oldest_key = next(iter(self._idempotency_cache))
                self._idempotency_cache.pop(oldest_key, None)
            return seen

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

    def _record_redis_success(self) -> None:
        self._redis_failures = 0
        self._redis_degraded_until = 0.0

    async def _record_redis_failure(self, operation: str, exc: Exception) -> None:
        self._redis_failures += 1
        logger.warning(
            "Bloom mesh Redis %s failed (%d/%d): %s",
            operation,
            self._redis_failures,
            REDIS_MAX_FAILURES,
            exc,
        )
        if self._redis_failures >= REDIS_MAX_FAILURES:
            self._redis_degraded_until = time.monotonic() + REDIS_RECONNECT_SECONDS
            await self._close_redis()

    async def _ensure_redis(self) -> None:
        if self._redis is not None or not self.redis_url:
            return
        if time.monotonic() < self._redis_degraded_until:
            return
        try:
            import redis.asyncio as redis

            self._redis = redis.from_url(
                self.redis_url,
                decode_responses=False,
                socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
                socket_timeout=REDIS_TIMEOUT_SECONDS,
                health_check_interval=30,
                max_connections=10,
                retry_on_timeout=True,
            )
            await asyncio.wait_for(self._redis.ping(), timeout=REDIS_TIMEOUT_SECONDS)
            self._record_redis_success()
        except Exception as exc:
            logger.warning("Bloom mesh Redis reconnect failed: %s", exc)
            await self._close_redis()
            self._redis_degraded_until = time.monotonic() + REDIS_RECONNECT_SECONDS

    async def _close_redis(self) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.aclose()
        except Exception as exc:
            logger.debug("Bloom mesh Redis close failed: %s", exc)
        finally:
            self._redis = None


BloomMeshSynchronizer = NeuralBloomMesh


class ReconcileBloom:
    """Coordinator class to reconcile Bloom Snapshots and manage flush loops."""

    def __init__(self, synchronizer: NeuralBloomMesh) -> None:
        self.synchronizer = synchronizer

    async def reconcile(self, reason: str = "manual_reconcile") -> dict[str, Any]:
        """Publish an immediate snapshot to all online nodes."""
        return await self.synchronizer.force_reconcile()

    async def flush(self, reason: str = "self_healing") -> dict[str, Any]:
        """Clear a saturated local filter and publish a fresh empty snapshot."""
        return await self.synchronizer.flush_overflowing_filter(reason=reason)


def _inc_metric(name: str, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().counter(name, description).inc()
    except Exception:
        logger.debug("Bloom mesh metric increment skipped for %s", name, exc_info=True)


def _set_metric(name: str, value: float | int | bool, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().gauge(name, description).set(float(value))
    except Exception:
        logger.debug("Bloom mesh metric gauge skipped for %s", name, exc_info=True)

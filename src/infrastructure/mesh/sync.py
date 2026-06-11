"""
Cyber Security Test Pipeline - Neural-Mesh Synchronization Utility.
Provides generic Redis Pub/Sub capabilities for cross-node state synchronization.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any, cast

import redis.asyncio as redis

logger = logging.getLogger(__name__)


# Bump when the wire format changes in a breaking way.
MESH_SYNC_SCHEMA_VERSION = 1
# Receivers will accept payloads with schema in [MIN_ACCEPTED, MAX_ACCEPTED].
# Anything outside that window is dropped with a metric increment.
MESH_SYNC_MIN_ACCEPTED_SCHEMA = 1
MESH_SYNC_MAX_ACCEPTED_SCHEMA = 1
# Idempotency window: number of recent message keys remembered per channel.
DEFAULT_IDEMPOTENCY_CACHE = 4096


def _stable_hash(payload: dict[str, Any]) -> str:
    """Deterministic SHA-256 hash for an idempotency / replay check."""
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class MeshSyncSnapshot:
    """Observable Redis mesh-sync counters for API consumers."""

    channel: str
    channel_scoped: str
    running: bool
    messages_published_total: int
    messages_received_total: int
    publish_failures_total: int
    listen_failures_total: int
    duplicates_dropped_total: int
    schema_rejected_total: int
    schema_version: int
    last_error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class MeshSync:
    """
    Redis Pub/Sub synchronization client.

    The wire format is a schema-versioned envelope::

        {
          "schema": 1,
          "msg_id": "<sender>-<uuid4>",
          "idempotency_key": "<sha256>",
          "sent_at": 1717000000.123,
          "sender": "<node-id-or-empty>",
          "payload": { ... caller's dict ... }
        }

    Receivers:
        * Drop messages whose ``schema`` is outside
          ``[MESH_SYNC_MIN_ACCEPTED_SCHEMA, MESH_SYNC_MAX_ACCEPTED_SCHEMA]``.
        * Drop messages whose ``idempotency_key`` has been seen within
          the rolling ``idempotency_cache_size`` window.

    Older un-versioned payloads (no ``schema`` field) are accepted and
    treated as schema 0 so MeshSync stays backwards compatible during a
    rolling upgrade; they are still de-duplicated using a content hash.
    """

    def __init__(
        self,
        redis_url: str,
        channel: str,
        *,
        sender_id: str | None = None,
        idempotency_cache_size: int = DEFAULT_IDEMPOTENCY_CACHE,
    ):
        self.redis_url = redis_url
        self.channel = channel
        self.sender_id = sender_id or ""
        self._client = redis.from_url(redis_url, decode_responses=True)
        self._pubsub = self._client.pubsub()
        self._running = False
        self._task: asyncio.Task[Any] | None = None
        self._messages_published_total = 0
        self._messages_received_total = 0
        self._publish_failures_total = 0
        self._listen_failures_total = 0
        self._duplicates_dropped_total = 0
        self._schema_rejected_total = 0
        self._last_error = ""
        self._idempotency_cache: OrderedDict[str, float] = OrderedDict()
        self._idempotency_cache_size = max(64, int(idempotency_cache_size))

    @property
    def channel_scoped(self) -> str:
        from src.core.tenant_context import TenantContext

        tenant_id = TenantContext.get_current_tenant()
        if tenant_id:
            return f"{tenant_id}:{self.channel}"
        return self.channel

    def _build_envelope(self, message: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Wrap a caller payload in the versioned envelope.

        Returns ``(envelope, idempotency_key)``.
        """
        if "idempotency_key" in message and isinstance(message["idempotency_key"], str):
            idem_key = message["idempotency_key"]
            payload = {k: v for k, v in message.items() if k != "idempotency_key"}
        else:
            payload = message
            idem_key = _stable_hash(payload)
        envelope = {
            "schema": MESH_SYNC_SCHEMA_VERSION,
            "msg_id": f"{self.sender_id or 'mesh'}-{uuid.uuid4().hex}",
            "idempotency_key": idem_key,
            "sent_at": time.time(),
            "sender": self.sender_id,
            "payload": payload,
        }
        return envelope, idem_key

    def _seen_idempotency_key(self, key: str) -> bool:
        """Return ``True`` if ``key`` was processed recently; record otherwise."""
        if not key:
            return False
        if key in self._idempotency_cache:
            # Refresh recency.
            self._idempotency_cache.move_to_end(key)
            return True
        self._idempotency_cache[key] = time.time()
        while len(self._idempotency_cache) > self._idempotency_cache_size:
            self._idempotency_cache.popitem(last=False)
        return False

    def _extract_payload(self, raw: Any) -> dict[str, Any] | None:
        """Decode a wire message and validate its schema/idempotency.

        Returns the caller-facing payload dict, or ``None`` if the
        message should be dropped (unknown schema, duplicate, malformed).
        """
        if not isinstance(raw, dict):
            return None

        # Backwards-compat: legacy publishers emit the bare payload (no
        # "schema" field). Treat them as schema=0 and de-duplicate using
        # a content hash so they participate in the idempotency window.
        if "schema" not in raw:
            draft_payload = cast("dict[str, Any]", raw)
            idem_key = _stable_hash(draft_payload)
            if self._seen_idempotency_key(idem_key):
                self._duplicates_dropped_total += 1
                _inc_metric(
                    "mesh_sync_duplicates_dropped_total",
                    "Total Redis mesh sync duplicate messages dropped",
                )
                return None
            return draft_payload

        schema = raw.get("schema")
        try:
            schema_int = -1 if schema is None else int(schema)
        except (TypeError, ValueError):
            schema_int = -1
        if not (MESH_SYNC_MIN_ACCEPTED_SCHEMA <= schema_int <= MESH_SYNC_MAX_ACCEPTED_SCHEMA):
            self._schema_rejected_total += 1
            _inc_metric(
                "mesh_sync_schema_rejected_total",
                "Total Redis mesh sync messages dropped due to unsupported schema",
            )
            logger.debug(
                "MeshSync: dropping payload with unsupported schema=%r on %s",
                schema,
                self.channel_scoped,
            )
            return None

        raw_payload = raw.get("payload")
        if not isinstance(raw_payload, dict):
            return None
        payload: dict[str, Any] = cast(dict[str, Any], raw_payload)

        idem_key = raw.get("idempotency_key")
        if idem_key is None or not isinstance(idem_key, str):
            idem_key = _stable_hash(payload)
        idem_key = str(idem_key)
        if self._seen_idempotency_key(idem_key):
            self._duplicates_dropped_total += 1
            _inc_metric(
                "mesh_sync_duplicates_dropped_total",
                "Total Redis mesh sync duplicate messages dropped",
            )
            return None

        return payload

    async def publish(self, message: dict[str, Any]) -> None:
        """Broadcast a message to the mesh.

        ``message`` may include an explicit ``idempotency_key`` string;
        otherwise one is derived deterministically from the payload
        content so repeated publishes of the same logical message are
        suppressed by every receiver's de-dup window.
        """
        envelope, _ = self._build_envelope(message)
        try:
            await self._client.publish(self.channel_scoped, json.dumps(envelope))
            self._messages_published_total += 1
            _inc_metric(
                "mesh_sync_messages_published_total",
                "Total Redis mesh sync messages published",
            )
        except Exception as e:
            self._publish_failures_total += 1
            self._last_error = str(e)
            _inc_metric(
                "mesh_sync_publish_failures_total",
                "Total Redis mesh sync publish failures",
            )
            logger.debug("MeshSync: Failed to publish message on %s: %s", self.channel_scoped, e)

    async def start_listening(self, callback: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Start a background loop to listen for messages and invoke the callback."""
        if self._running:
            return

        self._running = True
        await self._pubsub.subscribe(self.channel_scoped)
        self._task = asyncio.create_task(
            self._listen_loop(callback), name=f"mesh-sync-listener-{self.channel_scoped}"
        )
        logger.info("MeshSync: Subscribed to channel '%s'", self.channel_scoped)

    async def _listen_loop(self, callback: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Internal listen loop."""
        while self._running:
            try:
                # get_message with timeout to avoid blocking forever and allow shutdown
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if message and message["type"] == "message":
                    try:
                        raw = json.loads(message["data"])
                    except (ValueError, TypeError) as decode_exc:
                        self._listen_failures_total += 1
                        self._last_error = str(decode_exc)
                        _inc_metric(
                            "mesh_sync_listen_failures_total",
                            "Total Redis mesh sync listen failures",
                        )
                        logger.debug(
                            "MeshSync: malformed payload on %s: %s",
                            self.channel_scoped,
                            decode_exc,
                        )
                        continue
                    payload = self._extract_payload(raw)
                    if payload is None:
                        continue
                    self._messages_received_total += 1
                    _inc_metric(
                        "mesh_sync_messages_received_total",
                        "Total Redis mesh sync messages received",
                    )
                    await callback(payload)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._listen_failures_total += 1
                self._last_error = str(e)
                _inc_metric(
                    "mesh_sync_listen_failures_total",
                    "Total Redis mesh sync listen failures",
                )
                logger.debug("MeshSync: Listen loop error on %s: %s", self.channel_scoped, e)
                await asyncio.sleep(1.0)

    def health_snapshot(self) -> dict[str, Any]:
        """Return mesh sync telemetry without requiring dashboard coupling."""
        snapshot = MeshSyncSnapshot(
            channel=self.channel,
            channel_scoped=self.channel_scoped,
            running=self._running,
            messages_published_total=self._messages_published_total,
            messages_received_total=self._messages_received_total,
            publish_failures_total=self._publish_failures_total,
            listen_failures_total=self._listen_failures_total,
            duplicates_dropped_total=self._duplicates_dropped_total,
            schema_rejected_total=self._schema_rejected_total,
            schema_version=MESH_SYNC_SCHEMA_VERSION,
            last_error=self._last_error,
        )
        _set_metric(
            "mesh_sync_publish_failures",
            snapshot.publish_failures_total,
            "Current Redis mesh sync publish failures",
        )
        _set_metric(
            "mesh_sync_listen_failures",
            snapshot.listen_failures_total,
            "Current Redis mesh sync listen failures",
        )
        _set_metric(
            "mesh_sync_duplicates_dropped",
            snapshot.duplicates_dropped_total,
            "Current Redis mesh sync duplicates dropped",
        )
        _set_metric(
            "mesh_sync_schema_rejected",
            snapshot.schema_rejected_total,
            "Current Redis mesh sync schema rejections",
        )
        return snapshot.as_dict()

    async def stop(self) -> None:
        """Stop listening and close the Redis connection."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError as exc:
                logger.warning("Operation failed in sync.py: %s", exc, exc_info=True)  # noqa: BLE001
            self._task = None

        try:
            await self._pubsub.unsubscribe(self.channel_scoped)
            # Performance #4: Explicitly aclose pubsub to prevent connection leaks
            await self._pubsub.aclose()
            await self._client.close()
            logger.info("MeshSync: Disconnected from channel '%s'", self.channel_scoped)
        except Exception as e:
            logger.debug("MeshSync: Shutdown error: %s", e)


def _inc_metric(name: str, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().counter(name, description).inc()
    except Exception:
        logger.debug("MeshSync metric increment skipped for %s", name, exc_info=True)


def _set_metric(name: str, value: float | int | bool, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().gauge(name, description).set(float(value))
    except Exception:
        logger.debug("MeshSync metric gauge skipped for %s", name, exc_info=True)


__all__ = [
    "MESH_SYNC_SCHEMA_VERSION",
    "MESH_SYNC_MIN_ACCEPTED_SCHEMA",
    "MESH_SYNC_MAX_ACCEPTED_SCHEMA",
    "MeshSync",
    "MeshSyncSnapshot",
]

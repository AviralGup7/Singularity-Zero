"""Cross-Region WAL Replication & Stream Mirroring Service.

Replicates Write-Ahead Log (WAL) settlement intents and deltas across multiple
geographical regions / Redis stream instances for active-active synchronization.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    redis = None  # type: ignore
    REDIS_AVAILABLE = False


class WALReplicationRelay:
    """Mirrors WAL entries across regional Redis streams and reconciles peer deltas."""

    def __init__(
        self,
        local_wal: Any,
        peer_redis_urls: list[str] | None = None,
        run_id: str = "default_run",
    ) -> None:
        self.local_wal = local_wal
        self.peer_redis_urls = peer_redis_urls or []
        self.run_id = run_id
        self._peer_clients: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._init_peer_clients()

    def _init_peer_clients(self) -> None:
        if not REDIS_AVAILABLE:
            return
        for url in self.peer_redis_urls:
            try:
                client = redis.Redis.from_url(url, decode_responses=False, socket_timeout=3.0)
                self._peer_clients[url] = client
            except Exception as exc:
                logger.warning("WALReplicationRelay: Failed to connect to peer %s: %s", url, exc)

    def replicate_entry(self, entry: dict[str, Any]) -> dict[str, bool]:
        """Broadcast a local WAL entry / settlement intent to all connected peer Redis streams."""
        results: dict[str, bool] = {}
        if not self.peer_redis_urls:
            return results

        import json

        stream_key = f"cyber:wal:{self.run_id}"
        serialized_payload = json.dumps(entry, separators=(",", ":")).encode("utf-8")
        stream_data = {b"delta": serialized_payload, b"ts": str(time.time()).encode("ascii")}

        with self._lock:
            for url in self.peer_redis_urls:
                client = self._peer_clients.get(url)
                if client is None and REDIS_AVAILABLE:
                    try:
                        client = redis.Redis.from_url(
                            url, decode_responses=False, socket_timeout=3.0
                        )
                        self._peer_clients[url] = client
                    except Exception:
                        client = None

                if client is None:
                    results[url] = False
                    continue

                try:
                    client.xadd(stream_key, stream_data)
                    results[url] = True
                except Exception as exc:
                    logger.debug("WALReplicationRelay: Replication to %s failed: %s", url, exc)
                    results[url] = False

        return results

    def pull_peer_deltas(
        self, peer_url: str, last_id: str = "0-0", count: int = 100
    ) -> list[dict[str, Any]]:
        """Pull remote WAL entries from a peer Redis stream for reconciliation."""
        if not REDIS_AVAILABLE:
            return []

        import json

        client = self._peer_clients.get(peer_url)
        if client is None:
            try:
                client = redis.Redis.from_url(peer_url, decode_responses=False, socket_timeout=3.0)
                self._peer_clients[peer_url] = client
            except Exception as exc:
                logger.warning(
                    "WALReplicationRelay: Unable to connect to peer %s: %s", peer_url, exc
                )
                return []

        stream_key = f"cyber:wal:{self.run_id}"
        try:
            raw_streams = client.xread({stream_key: last_id}, count=count, block=None)
            if hasattr(raw_streams, "__await__"):
                return []
        except Exception as exc:
            logger.warning("WALReplicationRelay: xread failed from %s: %s", peer_url, exc)
            return []

        if not isinstance(raw_streams, list):
            return []

        deltas: list[dict[str, Any]] = []
        for _stream_name, messages in raw_streams:
            for msg_id, fields in messages:
                payload_bytes = fields.get(b"delta") or fields.get("delta")
                if payload_bytes:
                    try:
                        decoded = json.loads(payload_bytes.decode("utf-8"))
                        decoded["_wal_id"] = (
                            msg_id.decode("ascii") if isinstance(msg_id, bytes) else str(msg_id)
                        )
                        deltas.append(decoded)
                    except Exception as exc:
                        logger.debug(
                            "WALReplicationRelay: Malformed delta from %s: %s", peer_url, exc
                        )

        return deltas

    def reconcile_with_peer(self, peer_url: str, state_authority: Any | None = None) -> int:
        """Fetch remote deltas and apply any uncommitted settlement intents locally."""
        pulled = self.pull_peer_deltas(peer_url)
        applied_count = 0

        for entry in pulled:
            exec_id = entry.get("execution_id")
            if state_authority is not None and exec_id:
                if not state_authority.is_committed(exec_id):
                    from src.core.frontier.state_authority import SettlementIntent

                    if entry.get("_is_settlement_intent") or "state_delta" in entry:
                        intent = SettlementIntent.from_mapping(entry)
                        state_authority.append_settlement_intent(intent)
                        applied_count += 1

        return applied_count


__all__ = ["WALReplicationRelay"]

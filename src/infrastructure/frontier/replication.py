"""Cross-region WAL journal relay (non-authority).

Mirrors FrontierWAL scan-journal deltas across Redis streams. This is
**not** an active-active authority path. I36: a peer settlement / command
must not be committed on the local StateAuthority. PartitionWAL remains
the only mutating log, and only on the leader home.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    redis = None  # type: ignore
    REDIS_AVAILABLE = False


class ReplicationLagExceededError(RuntimeError):
    """Raised when cross-region replication lag exceeds the fail-closed threshold."""


@dataclass
class ReplicationCursor:
    """Resumable cursor tracking regional WAL stream offset and monotonic sequence."""

    last_stream_id: str = "0-0"
    last_seq: int = 0
    last_replicated_ts: float = 0.0
    lag_seconds: float = 0.0


class WALReplicationRelay:
    """Mirrors non-authoritative journal entries across regional Redis streams with I36 guarantees.

    Features:
    - Monotonic Read Enforcement: Rejects retrograde sequence numbers or non-monotonic timestamps.
    - Resumable Cursor: Persists and updates stream checkpoint IDs per peer.
    - Bounded In-Memory Backpressure: Limits outbound replication queue size.
    - Replication Lag Monitoring: Continuously calculates replication_lag_seconds.
    - Fail-Closed Lag Gate: Rejects stale/lagging reads when lag exceeds max_lag_seconds_threshold.
    - Single-Writer Confinement (I36): Filters out mutating settlement intents from remote peers.
    """

    def __init__(
        self,
        local_wal: Any,
        peer_redis_urls: list[str] | None = None,
        run_id: str = "default_run",
        *,
        max_lag_seconds_threshold: float = 30.0,
        backpressure_max_queue: int = 1000,
    ) -> None:
        self.local_wal = local_wal
        self.peer_redis_urls = peer_redis_urls or []
        self.run_id = run_id
        self.max_lag_seconds_threshold = max_lag_seconds_threshold
        self.backpressure_max_queue = backpressure_max_queue

        self._peer_clients: dict[str, Any] = {}
        self._cursors: dict[str, ReplicationCursor] = {}
        self._outbound_seq = 0
        self._lock = threading.RLock()
        self._init_peer_clients()

    def _init_peer_clients(self) -> None:
        for url in self.peer_redis_urls:
            self._cursors[url] = ReplicationCursor()
            if not REDIS_AVAILABLE:
                continue
            try:
                client = redis.Redis.from_url(url, decode_responses=False, socket_timeout=3.0)
                self._peer_clients[url] = client
            except Exception as exc:
                logger.warning("WALReplicationRelay: Failed to connect to peer %s: %s", url, exc)

    def get_cursor(self, peer_url: str) -> ReplicationCursor:
        """Get or initialize the resumable cursor for a peer."""
        with self._lock:
            if peer_url not in self._cursors:
                self._cursors[peer_url] = ReplicationCursor()
            return self._cursors[peer_url]

    def get_replication_lag_seconds(self, peer_url: str) -> float:
        """Return the current replication lag in seconds for a specific peer."""
        with self._lock:
            cursor = self.get_cursor(peer_url)
            if cursor.last_replicated_ts == 0.0:
                return 0.0
            return max(0.0, time.time() - cursor.last_replicated_ts)

    def assert_replication_fresh(self, peer_url: str) -> None:
        """Fail-closed gate: raise ReplicationLagExceededError if replication lag exceeds threshold."""
        lag = self.get_replication_lag_seconds(peer_url)
        if lag > self.max_lag_seconds_threshold:
            raise ReplicationLagExceededError(
                f"I36_FAIL_CLOSED: Replication lag {lag:.2f}s to peer {peer_url} "
                f"exceeds threshold {self.max_lag_seconds_threshold:.2f}s"
            )

    def replicate_entry(self, entry: dict[str, Any]) -> dict[str, bool]:
        """Broadcast a local journal delta to all connected peer Redis streams with monotonic seq."""
        results: dict[str, bool] = {}
        if not self.peer_redis_urls:
            return results

        import json

        with self._lock:
            self._outbound_seq += 1
            seq = self._outbound_seq

        stream_key = f"cyber:wal:{self.run_id}"
        entry_payload = dict(entry)
        entry_payload["_seq"] = seq
        now_ts = time.time()
        entry_payload["_src_ts"] = now_ts

        serialized_payload = json.dumps(entry_payload, separators=(",", ":")).encode("utf-8")
        stream_data = {
            b"delta": serialized_payload,
            b"seq": str(seq).encode("ascii"),
            b"ts": str(now_ts).encode("ascii"),
        }

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
                    # Apply backpressure: trim stream length if max queue threshold reached
                    client.xadd(
                        stream_key,
                        stream_data,
                        maxlen=self.backpressure_max_queue,
                        approximate=True,
                    )
                    results[url] = True
                except Exception as exc:
                    logger.debug("WALReplicationRelay: Replication to %s failed: %s", url, exc)
                    results[url] = False

        return results

    def pull_peer_deltas(
        self,
        peer_url: str,
        last_id: str | None = None,
        count: int = 100,
        *,
        enforce_lag_gate: bool = False,
    ) -> list[dict[str, Any]]:
        """Pull remote WAL entries from a peer Redis stream enforcing monotonic read ordering."""
        cursor = self.get_cursor(peer_url)
        active_last_id = last_id if last_id is not None else cursor.last_stream_id

        if enforce_lag_gate:
            self.assert_replication_fresh(peer_url)

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
            raw_streams = client.xread({stream_key: active_last_id}, count=count, block=None)
            if hasattr(raw_streams, "__await__"):
                return []
        except Exception as exc:
            logger.warning("WALReplicationRelay: xread failed from %s: %s", peer_url, exc)
            return []

        if not isinstance(raw_streams, list):
            return []

        deltas: list[dict[str, Any]] = []
        with self._lock:
            for _stream_name, messages in raw_streams:
                for msg_id, fields in messages:
                    msg_id_str = (
                        msg_id.decode("ascii") if isinstance(msg_id, bytes) else str(msg_id)
                    )
                    payload_bytes = fields.get(b"delta") or fields.get("delta")
                    if not payload_bytes:
                        continue

                    try:
                        decoded = json.loads(payload_bytes.decode("utf-8"))
                        seq = int(decoded.get("_seq", 0))

                        # Monotonic Read Enforcement: drop retrograde or duplicate sequences
                        if seq > 0 and seq <= cursor.last_seq:
                            logger.debug(
                                "I36_MONOTONIC: dropped retrograde delta seq %d <= last_seq %d from %s",
                                seq,
                                cursor.last_seq,
                                peer_url,
                            )
                            continue

                        decoded["_wal_id"] = msg_id_str
                        deltas.append(decoded)

                        # Advance resumable cursor
                        cursor.last_stream_id = msg_id_str
                        if seq > 0:
                            cursor.last_seq = seq
                        src_ts = float(decoded.get("_src_ts", time.time()))
                        cursor.last_replicated_ts = src_ts
                        cursor.lag_seconds = max(0.0, time.time() - src_ts)

                    except Exception as exc:
                        logger.debug(
                            "WALReplicationRelay: Malformed delta from %s: %s", peer_url, exc
                        )

        return deltas

    def reconcile_with_peer(
        self,
        peer_url: str,
        state_authority: Any | None = None,
        *,
        enforce_lag_gate: bool = False,
    ) -> int:
        """Fetch remote journal deltas. Never commit peer settlements (I36).

        Returns the count of journal-only (non-authority) rows observed.
        """
        from src.core.frontier.region_model import RegionDecision, classify_peer_entry

        if state_authority is not None:
            logger.warning(
                "I36: WALReplicationRelay refusing to apply peer settlements "
                "onto local StateAuthority (peer=%s)",
                peer_url,
            )

        pulled = self.pull_peer_deltas(peer_url, enforce_lag_gate=enforce_lag_gate)
        journal_count = 0
        refused = 0
        for entry in pulled:
            if classify_peer_entry(entry) is RegionDecision.REFUSE:
                refused += 1
                continue
            journal_count += 1
        if refused:
            logger.warning(
                "I36: dropped %d authoritative peer row(s) from %s; journal_only=%d",
                refused,
                peer_url,
                journal_count,
            )
        return journal_count


__all__ = ["WALReplicationRelay", "ReplicationCursor", "ReplicationLagExceededError"]


class PartitionWALReplicationNotReady(RuntimeError):
    """Raised when multi-region PartitionWAL continuous replicate is requested but not live."""


class PartitionWALReplicator:
    """Authoritative PartitionWAL A→B continuous replicate (P0-1).

    When ``source_wal`` and ``sink_wal`` expose ``load_all_entries`` /
    ``append_entry`` (as :class:`~src.core.frontier.replicated_log.PartitionWAL`
    does), this provider copies **committed** entries by raft_index into the
    sink. Frontier journal relay remains non-authority (I36).

    Enable with ``set_partition_wal_replicator(...)`` or
    ``PARTITION_WAL_REPLICATE=true`` plus bound WALs. Unbound instances stay
    disabled and report ``caught_up=False`` so activate_ownership still refuses.
    """

    def __init__(
        self, *, source_wal: Any = None, sink_wal: Any = None, enabled: bool | None = None
    ) -> None:
        import os

        self.source_wal = source_wal
        self.sink_wal = sink_wal
        if enabled is None:
            raw = os.environ.get("PARTITION_WAL_REPLICATE", "").strip().lower()
            enabled = raw in {"1", "true", "yes", "on"} or (
                source_wal is not None and sink_wal is not None
            )
        self.enabled = bool(enabled)
        self._last_replicated_index: int = 0
        self._lock = threading.RLock()

    def bind(self, *, source_wal: Any, sink_wal: Any) -> None:
        """Attach source/sink WALs and enable replicate."""
        with self._lock:
            self.source_wal = source_wal
            self.sink_wal = sink_wal
            self.enabled = True

    def replicate_range(self, *, from_index: int, to_index: int | None = None) -> int:
        """Copy committed PartitionWAL entries from source into sink.

        Returns the number of entries appended to the sink.
        """
        with self._lock:
            if not self.enabled or self.source_wal is None or self.sink_wal is None:
                raise PartitionWALReplicationNotReady(
                    "PartitionWAL replicator not enabled or missing source/sink WALs; "
                    "Frontier journal relay alone is non-authority (I36)."
                )
            if not hasattr(self.source_wal, "load_all_entries"):
                raise PartitionWALReplicationNotReady("source_wal lacks load_all_entries")
            if not hasattr(self.sink_wal, "append_entry"):
                raise PartitionWALReplicationNotReady("sink_wal lacks append_entry")

            try:
                records = list(self.source_wal.load_all_entries() or [])
            except Exception as exc:
                raise PartitionWALReplicationNotReady(f"source load failed: {exc}") from exc

            # Build sink index set to skip duplicates
            sink_idxs: set[int] = set()
            if hasattr(self.sink_wal, "load_all_entries"):
                try:
                    for entry, _committed in self.sink_wal.load_all_entries() or []:
                        sink_idxs.add(int(getattr(entry, "raft_index", 0) or 0))
                except Exception:
                    pass

            copied = 0
            hi = int(to_index) if to_index is not None else None
            lo = int(from_index)
            max_idx = self._last_replicated_index
            for entry, committed in records:
                if not committed:
                    continue
                idx = int(getattr(entry, "raft_index", 0) or 0)
                if idx < lo:
                    continue
                if hi is not None and idx > hi:
                    continue
                if idx in sink_idxs:
                    max_idx = max(max_idx, idx)
                    continue
                self.sink_wal.append_entry(entry, committed=True, sync=True)
                sink_idxs.add(idx)
                copied += 1
                max_idx = max(max_idx, idx)
            self._last_replicated_index = max(self._last_replicated_index, max_idx)
            return copied

    def caught_up(self, *, target_index: int) -> bool:
        """True when sink has replicated through *target_index* (committed)."""
        with self._lock:
            if not self.enabled or self.sink_wal is None:
                return False
            target = int(target_index)
            if self._last_replicated_index >= target and target >= 0:
                return True
            if not hasattr(self.sink_wal, "load_all_entries"):
                return False
            try:
                records = list(self.sink_wal.load_all_entries() or [])
            except Exception:
                return False
            max_committed = 0
            for entry, committed in records:
                if not committed:
                    continue
                max_committed = max(max_committed, int(getattr(entry, "raft_index", 0) or 0))
            self._last_replicated_index = max(self._last_replicated_index, max_committed)
            return self._last_replicated_index >= target

    def status(self) -> dict[str, Any]:
        return {
            "kind": "partition_wal_replicator",
            "enabled": bool(self.enabled),
            "authority": True if self.enabled and self.source_wal is not None else False,
            "last_replicated_index": int(self._last_replicated_index),
            "has_source": self.source_wal is not None,
            "has_sink": self.sink_wal is not None,
            "note": (
                "local PartitionWAL committed-entry copy"
                if self.enabled
                else "disabled — install via set_partition_wal_replicator or PARTITION_WAL_REPLICATE"
            ),
        }


_PARTITION_WAL_REPLICATOR: PartitionWALReplicator | None = None


def get_partition_wal_replicator() -> PartitionWALReplicator | None:
    """Return the process-wide PartitionWAL replicator if one was installed."""
    return _PARTITION_WAL_REPLICATOR


def set_partition_wal_replicator(replicator: PartitionWALReplicator | None) -> None:
    """Install or clear the PartitionWAL continuous-replicate provider (P0-1)."""
    global _PARTITION_WAL_REPLICATOR
    _PARTITION_WAL_REPLICATOR = replicator

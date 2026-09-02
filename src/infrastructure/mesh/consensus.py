"""
Cyber Security Test Pipeline - Neural-Mesh Consensus (Leader Election)

A Raft-lite leader election protocol backed by Redis leases.  The chosen
leader holds a single key ``mesh:leader:lease`` under ``SET NX PX`` with
a monotonically increasing term; all other nodes either yield to the
current lease holder or attempt to acquire it on the next maintenance
tick.

Why a Redis lease (and not the original Bully pick)?

* The previous implementation picked the lexicographically highest node
  id on every election, so an offline-but-still-reachable "old leader"
  could keep re-winning elections even after losing quorum.
* A lease that auto-expires gives a clean liveness story: if the leader
  dies, the TTL elapses, and the first node to ``SET NX`` afterwards
  becomes leader.
* ``term`` is bumped whenever a new leader takes over; this lets the
  gossip layer reject stale leadership advertisements when partitions
  heal.

When no Redis is configured (single-node dev / tests) the module falls
back to a deterministic Bully pick so the rest of the system still has a
stable leader id to read.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from src.infrastructure.mesh.gossip import GossipEngine
from src.infrastructure.queue.redis_config import (
    REDIS_TIMEOUT_SECONDS,
    redis_retry_async,
)

logger = logging.getLogger(__name__)


DEFAULT_LEASE_TTL_MS = int(os.getenv("MESH_LEADER_LEASE_TTL_MS", "15000"))
DEFAULT_REFRESH_INTERVAL_SEC = float(os.getenv("MESH_LEADER_REFRESH_SEC", "5.0"))
DEFAULT_ELECTION_TIMEOUT_SEC = float(os.getenv("MESH_LEADER_ELECTION_TIMEOUT_SEC", "10.0"))
DEFAULT_MAINTENANCE_INTERVAL_SEC = float(os.getenv("MESH_LEADER_MAINTENANCE_INTERVAL_SEC", "3.0"))
LEASE_KEY = "mesh:leader:lease"


@dataclass
class _LeaderRecord:
    """In-memory mirror of the Redis lease value."""

    node_id: str
    term: int
    acquired_at: float
    fencing_token: int = 0

    def to_json(self) -> str:
        return json.dumps(
            {
                "node_id": self.node_id,
                "term": self.term,
                "acquired_at": self.acquired_at,
                "fencing_token": self.fencing_token,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> _LeaderRecord:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        payload = json.loads(raw)
        term = int(payload["term"])
        return cls(
            node_id=str(payload["node_id"]),
            term=term,
            acquired_at=float(payload.get("acquired_at", 0.0)),
            fencing_token=int(payload.get("fencing_token", term)),
        )

    @classmethod
    def empty(cls) -> _LeaderRecord:
        return cls(node_id="", term=0, acquired_at=0.0, fencing_token=0)


class MeshConsensus:
    """
    Lease-backed leader election for the neural mesh.

    Public API (kept stable for callers that already use it):

    * ``leader_id``          - current best-known leader (may be the local
                               node, a known peer, or ``None`` if neither).
    * ``term``               - monotonic term of the current leader.
    * ``is_leader()``        - ``True`` if the local node holds the lease.
    * ``run_maintenance()``  - coroutine: tick forever, refreshing /
                               acquiring the lease as needed.
    * ``start_election()``   - force an immediate election attempt.
    * ``leader_record()``    - snapshot of the current lease (for tests).
    """

    def __init__(
        self,
        gossip: GossipEngine,
        *,
        redis_url: str | None = None,
        lease_ttl_ms: int = DEFAULT_LEASE_TTL_MS,
        refresh_interval_sec: float = DEFAULT_REFRESH_INTERVAL_SEC,
        election_timeout_sec: float = DEFAULT_ELECTION_TIMEOUT_SEC,
        maintenance_interval_sec: float = DEFAULT_MAINTENANCE_INTERVAL_SEC,
        redis_client: Any = None,
        region: str | None = None,
        rtt_multiplier: float = 10.0,
    ) -> None:
        self.gossip = gossip
        self.leader_id: str | None = None
        self.term: int = 0
        self._election_in_progress = False
        self._redis_url = redis_url or os.getenv("REDIS_URL")
        self.region = region or os.getenv("MESH_REGION", "local")
        self.rtt_multiplier = max(2.0, float(rtt_multiplier))

        # Per-region base timeout scaling
        base_timeout = float(election_timeout_sec)
        if self.region in {"cross-region", "wan", "multi-region"}:
            base_timeout = max(base_timeout, 30.0)

        self._lease_ttl_ms = max(1000, int(lease_ttl_ms))
        self._refresh_interval_sec = max(0.5, float(refresh_interval_sec))
        self._base_election_timeout_sec = max(1.0, base_timeout)
        self._maintenance_interval_sec = max(0.5, float(maintenance_interval_sec))

        # refresh interval must be well under the TTL to avoid losing the
        # lease due to a single slow tick.
        if self._refresh_interval_sec * 3.0 > (self._lease_ttl_ms / 1000.0):
            self._refresh_interval_sec = max(0.5, (self._lease_ttl_ms / 1000.0) / 3.0)
        self._redis: Any = redis_client  # injected for tests; lazily created otherwise
        self._last_renewed_at = 0.0
        self._last_redis_error: str | None = None
        self._lease: _LeaderRecord = _LeaderRecord.empty()
        self._stop_event = asyncio.Event()

    @property
    def election_timeout_sec(self) -> float:
        """Dynamically compute effective election timeout based on observed peer RTTs."""
        stats = getattr(self.gossip, "peer_stats", {})
        rtts = []
        if isinstance(stats, dict):
            for p_stat in stats.values():
                rtt = getattr(p_stat, "round_trip_time", getattr(p_stat, "rtt", 0.0))
                if rtt and rtt > 0:
                    rtts.append(rtt)
        if rtts:
            import statistics

            med_rtt = statistics.median(rtts)
            # 10x median RTT with base timeout floor
            return max(self._base_election_timeout_sec, med_rtt * self.rtt_multiplier)
        return self._base_election_timeout_sec

    # ------------------------------------------------------------------ public

    async def run_maintenance(self) -> None:
        """Periodic tick: refresh our own lease or try to claim the key."""
        while not self._stop_event.is_set():
            try:
                if not self.gossip.local_node:
                    await self._sleep(self._maintenance_interval_sec)
                    continue

                if self.is_leader():
                    await self._refresh_lease()
                else:
                    await self._maybe_takeover()

                self._publish_leader_to_gossip()
            except Exception:
                logger.exception("MeshConsensus maintenance tick failed")
            await self._sleep(self._maintenance_interval_sec)

    def stop(self) -> None:
        """Signal the maintenance loop to exit on next tick."""
        self._stop_event.set()

    async def start_election(self) -> bool:
        """Force an immediate election attempt.

        Awaits the in-flight attempt so callers that need an authoritative
        ``leader_id`` after the call can rely on it.  Returns ``True`` if
        the local node won the election.
        """
        if self._election_in_progress:
            return False
        self._election_in_progress = True
        try:
            if not self.gossip.local_node:
                return False
            if self._redis is None and not self._redis_url:
                return self._fallback_local_election()
            client = await self._ensure_redis()
            if client is None:
                return self._fallback_local_election()
            return await self._try_acquire(client, force_term_bump=True)
        finally:
            self._election_in_progress = False

    def is_leader(self) -> bool:
        return self.leader_id == self.gossip.local_node.id

    def leader_record(self) -> _LeaderRecord:
        return _LeaderRecord(
            node_id=self._lease.node_id,
            term=self._lease.term,
            acquired_at=self._lease.acquired_at,
            fencing_token=getattr(self._lease, "fencing_token", self._lease.term),
        )

    @property
    def fencing_token(self) -> int:
        """Monotonic storage fencing token bound to leader lease (Item 9)."""
        if not self.is_leader():
            return 0
        return getattr(self._lease, "fencing_token", self.term)

    def validate_fencing_token(self, token: int) -> bool:
        """Validate if token is currently valid, unexpired, and held by local node."""
        return self.is_leader() and token == self.fencing_token and token > 0

    # ----------------------------------------------------------------- internal

    async def _refresh_lease(self) -> None:
        """If we still hold the lease, bump the TTL; otherwise yield."""
        client = await self._ensure_redis()
        if client is None:
            return
        current = await self._read_lease(client)
        if current is None:
            # We thought we were leader but the lease vanished (TTL
            # expired or Redis flushed); clear state and let the next
            # tick attempt to take over.
            self.leader_id = None
            self._lease = _LeaderRecord.empty()
            return
        if current.node_id != self.gossip.local_node.id or current.term != self.term:
            # A different node has the lease (likely the term was bumped
            # by a partition-heal).  Yield gracefully.
            self.leader_id = current.node_id
            self.term = current.term
            self._lease = current
            return
        refreshed = _LeaderRecord(
            node_id=self.gossip.local_node.id,
            term=self.term,
            acquired_at=current.acquired_at if current.acquired_at is not None else time.time(),
        )
        ok = await self._set_lease(client, refreshed, ttl_ms=self._lease_ttl_ms)
        if ok:
            self._last_renewed_at = time.time()
            self._last_redis_error = None
        else:
            self.leader_id = None
            self._lease = _LeaderRecord.empty()

    async def _maybe_takeover(self) -> None:
        """If the current lease has expired or the holder is dead, claim it."""
        client = await self._ensure_redis()
        if client is None:
            return
        current = await self._read_lease(client)
        if current is not None:
            holder_alive = (
                current.node_id == self.gossip.local_node.id or current.node_id in self.gossip.peers
            )
            ttl_remaining_ms = await self._ttl_ms(client)
            lease_still_fresh = (
                ttl_remaining_ms is None or ttl_remaining_ms > self.election_timeout_sec * 1000
            )
            if holder_alive and lease_still_fresh and current.term >= self.term:
                self.leader_id = current.node_id
                self.term = current.term
                self._lease = current
                return

            # Pre-Vote Guard: partitioned/isolated nodes must not trigger disruptive term bumps
            if not self._passes_prevote_check():
                logger.debug(
                    "MeshConsensus: pre-vote failed — skipping takeover attempt to prevent split-brain"
                )
                return

            # Lease is stale: the term must be bumped on takeover so any
            # zombie leader with an old term can be told to step down.
            new_term = max(self.term, current.term) + 1
        else:
            if not self._passes_prevote_check():
                return
            new_term = self.term + 1
        record = _LeaderRecord(
            node_id=self.gossip.local_node.id,
            term=new_term,
            acquired_at=time.time(),
        )
        await self._try_acquire(client, record=record)

    def _passes_prevote_check(self) -> bool:
        """Pre-vote validation: ensure local node is connected to at least minority peers before challenging leader."""
        peers = getattr(self.gossip, "peers", {})
        if not peers:
            return True  # Single-node mode passes
        alive_peers = sum(
            1 for p in peers.values() if getattr(p, "status", "alive") in {"alive", "suspect"}
        )
        total_nodes = len(peers) + 1
        quorum = (total_nodes // 2) + 1
        return (alive_peers + 1) >= quorum

    async def _try_acquire(
        self,
        client: Any,
        *,
        force_term_bump: bool = False,
        record: _LeaderRecord | None = None,
    ) -> bool:
        record = record or _LeaderRecord(
            node_id=self.gossip.local_node.id,
            term=self.term + (1 if force_term_bump else 0),
            acquired_at=time.time(),
        )
        ok = await self._set_lease(client, record, ttl_ms=self._lease_ttl_ms, nx=True)
        if not ok:
            current = await self._read_lease(client)
            if current is not None:
                self.leader_id = current.node_id
                self.term = current.term
                self._lease = current
            return False
        self.leader_id = record.node_id
        self.term = record.term
        self._lease = record
        self._last_renewed_at = time.time()
        self._last_redis_error = None
        logger.info(
            "Acquired mesh leader lease node=%s term=%d ttl_ms=%d",
            record.node_id,
            record.term,
            self._lease_ttl_ms,
        )
        return True

    def _fallback_local_election(self) -> bool:
        """Offline (no-Redis) fallback: deterministic Bully pick.

        Returns ``True`` if the local node won.
        """
        candidates = list(self.gossip.peers.values()) + [self.gossip.local_node]
        winner = max(candidates, key=lambda n: n.id)
        self.leader_id = winner.id
        self.term += 1
        self._lease = _LeaderRecord(node_id=winner.id, term=self.term, acquired_at=time.time())
        return winner.id == self.gossip.local_node.id

    def _publish_leader_to_gossip(self) -> None:
        """Push the current leader into the gossip engine for fan-out."""
        engine = getattr(self.gossip, "engine", None) or self.gossip
        if self.leader_id and hasattr(engine, "leader_id"):
            try:
                engine.leader_id = self.leader_id
            except Exception:
                logger.debug("Failed to push leader_id into gossip engine", exc_info=True)

    async def _ensure_redis(self) -> Any | None:
        if self._redis is not None:
            return self._redis
        if not self._redis_url:
            return None
        try:
            import redis.asyncio as redis

            client = redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
                socket_timeout=REDIS_TIMEOUT_SECONDS,
            )
            await asyncio.wait_for(client.ping(), timeout=REDIS_TIMEOUT_SECONDS)
            self._redis = client
            self._last_redis_error = None
            return client
        except Exception as exc:
            self._last_redis_error = repr(exc)
            logger.warning("MeshConsensus Redis unavailable: %s", exc, exc_info=True)
            self._redis = None
            return None

    async def _read_lease(self, client: Any) -> _LeaderRecord | None:
        async def _op() -> str | None:
            value: Any = await client.get(LEASE_KEY)
            if value is None:
                return None
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            return str(value)

        try:
            raw = await redis_retry_async(_op, label="read_lease")
        except Exception as exc:
            self._last_redis_error = repr(exc)
            logger.warning("Failed to read leader lease: %s", exc, exc_info=True)
            return None
        if raw is None:
            return None
        try:
            return _LeaderRecord.from_json(raw)
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("Malformed leader lease payload: %s", exc)
            return None

    async def _ttl_ms(self, client: Any) -> int | None:
        async def _op() -> int:
            return int(await client.pttl(LEASE_KEY))

        try:
            return await redis_retry_async(_op, label="lease_ttl")
        except Exception:
            logger.warning("Failed to read lease TTL", exc_info=True)
            return None

    async def _set_lease(
        self,
        client: Any,
        record: _LeaderRecord,
        *,
        ttl_ms: int,
        nx: bool = False,
    ) -> bool:
        async def _op() -> bool:
            result = await client.set(LEASE_KEY, record.to_json(), px=ttl_ms, nx=nx)
            # ``redis.asyncio`` returns ``True``/``None`` for ``SET ... NX``.
            return bool(result)

        try:
            return await redis_retry_async(_op, label="set_lease")
        except Exception as exc:
            self._last_redis_error = repr(exc)
            logger.warning("Failed to write leader lease: %s", exc, exc_info=True)
            return False

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except TimeoutError:
            return

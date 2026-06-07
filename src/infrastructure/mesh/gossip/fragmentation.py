"""
UDP fragmentation, per-peer rate-limiting, and message-id deduplication
for the gossip mesh.

The mesh is a UDP protocol and our on-wire envelopes are JSON.  When an
envelope's serialized form exceeds the safe MTU (~1300 bytes) the
``Fragmenter`` splits it into multiple ``fragment`` envelopes.  The
``Reassembler`` reassembles them by ``msg_id`` on the receiver side and
forwards the original payload to the existing protocol handler.

A small in-memory ``PeerRateLimiter`` drops packets from peers that
exceed a configurable per-second budget (default 200 pps) and a bounded
``MessageDeduper`` ring buffer discards replays.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Safe UDP MTU: leaves room for IPv6 + UDP + auth headers without
# fragmentation at the IP layer.  Tunable via MESH_FRAGMENT_THRESHOLD.
DEFAULT_FRAGMENT_THRESHOLD = int(
    os.getenv("MESH_FRAGMENT_THRESHOLD", str(1300))
)
# Each fragment is JSON-encoded before send, so reserve room for the
# outer envelope fields (msg_id, frag_index, frag_total, sig, ...).
DEFAULT_FRAGMENT_PAYLOAD = int(
    os.getenv("MESH_FRAGMENT_PAYLOAD", str(1024))
)
# Max reassembly window per msg_id (seconds).  After this we drop the
# partial buffer and increment ``reassembly_timeouts_total``.
DEFAULT_REASSEMBLY_TTL_SEC = float(
    os.getenv("MESH_REASSEMBLY_TTL_SEC", "5.0")
)
# Max number of in-flight reassemblies.  Caps memory under DoS.
DEFAULT_REASSEMBLY_MAX_MESSAGES = int(
    os.getenv("MESH_REASSEMBLY_MAX_MESSAGES", "256")
)
# Per-peer packet rate limit (packets per second).
DEFAULT_PEER_RATE_LIMIT_PPS = int(
    os.getenv("MESH_PEER_RATE_LIMIT_PPS", "200")
)
# Per-peer burst capacity.  Tokens refill at ``PEER_RATE_LIMIT_PPS``.
DEFAULT_PEER_BURST = int(
    os.getenv("MESH_PEER_BURST", str(max(50, DEFAULT_PEER_RATE_LIMIT_PPS)))
)
# Message-id dedup window.  Anything older is forgotten.
DEFAULT_DEDUP_WINDOW = int(os.getenv("MESH_DEDUP_WINDOW", "1024"))


# ---------------------------------------------------------------- fragmenter


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(raw: str) -> bytes:
    return base64.b64decode(raw.encode("ascii"))


@dataclass
class FragmentPlan:
    """A pre-computed fragmentation plan for a single envelope."""

    msg_id: str
    envelopes: list[bytes]


class Fragmenter:
    """Split oversized envelopes into smaller fragments.

    The ``Fragmenter`` is stateless and thread-safe: callers can hand it
    the raw bytes returned by ``_make_envelope`` and get back either a
    single fragment (when the input is small enough) or a list of
    fragment envelopes.
    """

    def __init__(
        self,
        *,
        threshold: int = DEFAULT_FRAGMENT_THRESHOLD,
        payload_size: int = DEFAULT_FRAGMENT_PAYLOAD,
    ) -> None:
        self.threshold = max(256, int(threshold))
        self.payload_size = max(128, int(payload_size))

    def maybe_split(self, raw_envelope: bytes, msg_id: str) -> list[bytes]:
        """Return a list of envelopes ready for ``sendto``.

        If the input fits within the threshold, the list contains
        exactly one entry (the original bytes).  Otherwise the bytes
        are split into base64-fragmented ``fragment`` envelopes.
        """
        if len(raw_envelope) <= self.threshold:
            return [raw_envelope]
        chunk = self.payload_size
        total = (len(raw_envelope) + chunk - 1) // chunk
        out: list[bytes] = []
        # ``fragment_envelope`` is the JSON-encoded wrapper we'll hand
        # to the transport.  We can't reuse ``_make_envelope`` here
        # because that re-signs and re-stamps ``sent_at``; fragments
        # are anonymous at the gossip layer (no signature on the
        # inner chunk - the receiver re-validates the *reassembled*
        # envelope).
        encoded_chunks: list[str] = []
        for i in range(total):
            start = i * chunk
            encoded_chunks.append(_b64encode(raw_envelope[start : start + chunk]))
        # Pack all chunks into a single envelope when the JSON-wrapped
        # form still fits.  This is the common case (3-5 fragments
        # typically fit in one UDP datagram).
        from src.infrastructure.mesh.gossip.engine import (
            _canonical_json,  # local import to avoid cycle
        )

        wrapper = {
            "kind": "fragment",
            "msg_id": msg_id,
            "frag_index": 0,
            "frag_total": 1,
            "chunks": encoded_chunks,
        }
        candidate = _canonical_json(wrapper)
        if len(candidate) <= self.threshold:
            return [candidate]
        # Fall back to one fragment per chunk when even the wrapper is
        # too big.  Each gets its own ``frag_index``/``frag_total``.
        out = []
        for i, chunk_b64 in enumerate(encoded_chunks):
            wrapper_i = {
                "kind": "fragment",
                "msg_id": msg_id,
                "frag_index": i,
                "frag_total": total,
                "chunks": [chunk_b64],
            }
            out.append(_canonical_json(wrapper_i))
        return out


# ---------------------------------------------------------------- reassembler


@dataclass
class _ReassemblyBuffer:
    chunks: dict[int, str] = field(default_factory=dict)
    total: int = 0
    started_at: float = 0.0


class Reassembler:
    """Buffer incoming fragments and yield complete envelopes.

    The ``Reassembler`` exposes a single ``ingest`` method that returns
    either a complete bytes payload (which the caller should feed to
    the normal protocol handler) or ``None`` if more fragments are
    still needed.  Expired or evicted buffers are silently dropped and
    counted in ``reassembly_timeouts_total`` / ``reassembly_evicted_total``.
    """

    def __init__(
        self,
        *,
        ttl_sec: float = DEFAULT_REASSEMBLY_TTL_SEC,
        max_messages: int = DEFAULT_REASSEMBLY_MAX_MESSAGES,
        time_source: Callable[[], float] = time.time,
    ) -> None:
        self._ttl = max(0.5, float(ttl_sec))
        self._max = max(8, int(max_messages))
        self._now = time_source
        self._buffers: OrderedDict[str, _ReassemblyBuffer] = OrderedDict()
        self._lock = threading.Lock()
        self.reassembly_timeouts_total = 0
        self.reassembly_evicted_total = 0
        self.reassembly_completed_total = 0

    def ingest(self, envelope: dict) -> bytes | None:
        """Process one fragment envelope; return reassembled bytes or ``None``."""
        msg_id = str(envelope.get("msg_id", ""))
        if not msg_id:
            return None
        total = int(envelope.get("frag_total", 1))
        chunks = envelope.get("chunks") or []
        if total <= 0 or not chunks:
            return None
        now = self._now()
        with self._lock:
            self._gc_locked(now)
            buf = self._buffers.get(msg_id)
            if buf is None:
                if len(self._buffers) >= self._max:
                    # Evict the oldest partial message - signals an
                    # attacker or a network that never delivers the
                    # remaining chunks.
                    self._buffers.popitem(last=False)
                    self.reassembly_evicted_total += 1
                buf = _ReassemblyBuffer(total=total, started_at=now)
                self._buffers[msg_id] = buf
            buf.total = total
            for i, chunk in enumerate(chunks):
                idx = int(envelope.get("frag_index", i))
                buf.chunks[idx] = str(chunk)
            if len(buf.chunks) < total:
                # Mark as recently used so it isn't GC'd before the
                # remaining chunks arrive.
                self._buffers.move_to_end(msg_id)
                return None
            # Complete - decode and remove the buffer.
            ordered = [buf.chunks[i] for i in sorted(buf.chunks)]
            self._buffers.pop(msg_id, None)
        self.reassembly_completed_total += 1
        try:
            return b"".join(_b64decode(part) for part in ordered)
        except (ValueError, TypeError) as exc:
            logger.warning("Fragment reassembly decode failed: %s", exc)
            return None

    def _gc_locked(self, now: float) -> None:
        expired: list[str] = []
        for msg_id, buf in self._buffers.items():
            if (now - buf.started_at) > self._ttl:
                expired.append(msg_id)
            else:
                # Buffers are kept in insertion order; once we hit a
                # non-expired one we can stop.
                break
        for msg_id in expired:
            self._buffers.pop(msg_id, None)
            self.reassembly_timeouts_total += 1


# ---------------------------------------------------------------- rate limit


class PeerRateLimiter:
    """Token-bucket per-peer rate limiter for incoming gossip packets.

    Defaults: ``rate_pps`` tokens per second, ``burst`` token capacity.
    Anything over budget is dropped and counted in
    ``dropped_packets_total`` and ``dropped_peers`` is bumped so a
    single misbehaving peer can't take down the whole mesh.
    """

    def __init__(
        self,
        *,
        rate_pps: int = DEFAULT_PEER_RATE_LIMIT_PPS,
        burst: int = DEFAULT_PEER_BURST,
        time_source: Callable[[], float] = time.time,
    ) -> None:
        self._rate = max(1, int(rate_pps))
        self._burst = max(self._rate, int(burst))
        self._now = time_source
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self.dropped_packets_total = 0
        self.dropped_peers: set[str] = set()
        self.allowed_packets_total = 0

    def allow(self, peer: str) -> bool:
        if not peer:
            peer = "unknown"
        now = self._now()
        with self._lock:
            tokens, last = self._buckets.get(peer, (float(self._burst), now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            if tokens < 1.0:
                self._buckets[peer] = (tokens, now)
                self.dropped_packets_total += 1
                self.dropped_peers.add(peer)
                return False
            tokens -= 1.0
            self._buckets[peer] = (tokens, now)
            self.allowed_packets_total += 1
            return True

    def reset_peer(self, peer: str) -> None:
        with self._lock:
            self._buckets.pop(peer, None)
            self.dropped_peers.discard(peer)


# ---------------------------------------------------------------- dedup


class MessageDeduper:
    """Bounded LRU dedup of recent ``msg_id`` values."""

    def __init__(self, *, window: int = DEFAULT_DEDUP_WINDOW) -> None:
        self._window = max(64, int(window))
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        self.duplicates_total = 0
        self.admitted_total = 0

    def seen(self, msg_id: str) -> bool:
        """Return ``True`` if this is a new message; ``False`` if duplicate."""
        if not msg_id:
            return True
        with self._lock:
            now = time.time()
            if msg_id in self._seen:
                self._seen.move_to_end(msg_id)
                self.duplicates_total += 1
                return False
            self._seen[msg_id] = now
            self.admitted_total += 1
            if len(self._seen) > self._window:
                self._seen.popitem(last=False)
            return True


__all__ = [
    "DEFAULT_FRAGMENT_THRESHOLD",
    "DEFAULT_FRAGMENT_PAYLOAD",
    "DEFAULT_REASSEMBLY_TTL_SEC",
    "DEFAULT_REASSEMBLY_MAX_MESSAGES",
    "DEFAULT_PEER_RATE_LIMIT_PPS",
    "DEFAULT_PEER_BURST",
    "DEFAULT_DEDUP_WINDOW",
    "Fragmenter",
    "FragmentPlan",
    "Reassembler",
    "PeerRateLimiter",
    "MessageDeduper",
]

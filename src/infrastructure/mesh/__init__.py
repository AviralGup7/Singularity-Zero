"""Mesh subsystem — distributed P2P coordination layer.

Architecture Overview
=====================

The mesh subsystem implements a decentralized coordination layer for
multi-node deployments. It is intentionally complex because it solves
inherently difficult distributed systems problems.

Components
----------

1. **Gossip Protocol** (``gossip/``)
   SWIM-based protocol for node discovery, failure detection, and state
   dissemination. Uses UDP with HMAC-SHA256 authentication.
   - ``GossipEngine``: Main engine with reliable send, heartbeat, dedup
   - ``GossipProtocol``: asyncio.DatagramProtocol implementation
   - ``PeerTracker``: Tracks peer health and membership
   - ``Fragmentation``: Handles oversized messages via chunking

2. **Consensus** (``consensus.py``)
   Raft-lite leader election using Redis SET NX PX for lease acquisition.
   Falls back to deterministic Bully pick (lexicographically highest node ID)
   when Redis is unavailable. Monotonic terms prevent stale leader re-election.

3. **Bloom Mesh** (``../frontier/bloom_mesh.py``)
   Redis pub/sub synchronization of Bloom filter snapshots across nodes.
   VectorClock-based ordering ensures consistency. Used for URL deduplication
   in the scan pipeline.

4. **Sharding** (``sharding.py``)
   Weighted consistent hashing for distributing scan work across nodes.
   Region/zone-aware placement for fault isolation.

5. **Sync** (``sync.py``)
   Redis-backed state synchronization for cross-node data sharing.

6. **Telemetry** (via lifespan mesh_telemetry_pulse)
   Periodic CPU/RAM/job metrics broadcast to all peers.

Design Decisions
----------------

- **UDP over TCP** for gossip: Lower latency, acceptable for eventually-
  consistent state. Reliable delivery is implemented at the application layer
  with exponential backoff + jitter.

- **Redis as optional transport**: Consensus and bloom sync use Redis when
  available for faster propagation. The system degrades gracefully to pure
  gossip when Redis is absent.

- **HMAC authentication**: All gossip messages are signed with a shared
  secret (MESH_SECRET env var). Prevents rogue node injection.

- **Feature flags**: Each component (gossip, consensus, bloom mesh) can be
  independently disabled via FeatureFlags for development and testing.

When to Modify
--------------

- Adding new node metadata: Extend ``MeshNode`` in ``gossip/models.py``
- Changing failure detection: Modify ``failure_detector.py`` and heartbeats
- Adding new message types: Add to ``gossip/protocol.py`` and ``engine.py``
- Changing leader election: Modify ``consensus.py``
- Adjusting shard weights: Modify ``sharding.py``

When NOT to Modify
------------------

- If the system works correctly under load, the complexity is justified.
- Do not simplify consensus without understanding the failure modes.
- Do not remove gossip authentication without a security review.
"""

from __future__ import annotations

__all__ = [
    "gossip",
    "consensus",
    "sharding",
    "sync",
    "manifest",
    "balancer",
    "bidder",
]

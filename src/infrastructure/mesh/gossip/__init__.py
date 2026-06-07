"""Gossip protocol mesh package – public re-exports."""

from __future__ import annotations

from typing import Any

from src.infrastructure.mesh.gossip.engine import GossipEngine
from src.infrastructure.mesh.gossip.fragmentation import (
    DEFAULT_FRAGMENT_THRESHOLD,
    Fragmenter,
    MessageDeduper,
    PeerRateLimiter,
    Reassembler,
)
from src.infrastructure.mesh.gossip.models import MeshNode, PeerHealthStats
from src.infrastructure.mesh.gossip.peer import PeerTracker
from src.infrastructure.mesh.gossip.protocol import GossipProtocol
from src.infrastructure.mesh.gossip.rate_limiter import RateLimiter
from src.infrastructure.mesh.gossip.reconciler import reconcile_payload
from src.infrastructure.mesh.gossip.serializer import canonical_json, sign, verify

__all__ = [
    "GossipEngine",
    "GossipProtocol",
    "MeshNode",
    "PeerTracker",
    "PeerHealthStats",
    "RateLimiter",
    "reconcile_payload",
    "canonical_json",
    "sign",
    "verify",
    "Fragmenter",
    "Reassembler",
    "PeerRateLimiter",
    "MessageDeduper",
    "DEFAULT_FRAGMENT_THRESHOLD",
]

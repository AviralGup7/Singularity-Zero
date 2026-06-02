"""Gossip protocol mesh package – public re-exports."""

from __future__ import annotations

from typing import Any

from src.infrastructure.mesh.gossip.engine import GossipEngine
from src.infrastructure.mesh.gossip.failure_detector import FailureDetector
from src.infrastructure.mesh.gossip.heartbeat import TelemetryCollector
from src.infrastructure.mesh.gossip.models import MeshNode, PeerHealthStats
from src.infrastructure.mesh.gossip.peer import PeerTracker
from src.infrastructure.mesh.gossip.protocol import GossipProtocol
from src.infrastructure.mesh.gossip.rate_limiter import RateLimiter
from src.infrastructure.mesh.gossip.reconciler import reconcile_payload as reconcile
from src.infrastructure.mesh.gossip.serializer import (
    canonical_json,
    make_envelope,
    parse_envelope,
    sign,
    verify,
)

__all__ = [
    "GossipEngine",
    "FailureDetector",
    "GossipProtocol",
    "TelemetryCollector",
    "MeshNode",
    "PeerHealthStats",
    "PeerTracker",
    "RateLimiter",
    "canonical_json",
    "sign",
    "verify",
    "make_envelope",
    "parse_envelope",
    "reconcile",
]

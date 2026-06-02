from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class MeshNode:
    """Metadata for a node in the gossip mesh."""

    id: str
    host: str
    port: int
    status: str = "alive"
    cpu_usage: float = 0.0
    ram_available_mb: float = 0.0
    active_jobs: int = 0
    last_seen: float = field(default_factory=time.time)


@dataclass
class PeerHealthStats:
    """Operational counters used by mesh health and topology views."""

    sent: int = 0
    received: int = 0
    failed: int = 0
    retry_count: int = 0
    heartbeat_misses: int = 0
    last_latency_ms: float | None = None
    last_heartbeat: float | None = None
    outbound_throughput: int = 0
    inbound_throughput: int = 0


@dataclass(frozen=True)
class MeshHealthSnapshot:
    """Small mesh health summary consumable by shared API layers."""

    node_count: int
    healthy_node_count: int
    unhealthy_node_count: int
    suspect_node_count: int
    dead_node_count: int
    gossip_sync_failures_total: int
    heartbeat_misses_total: int
    avg_latency_ms: float
    drop_rate: float
    active_heartbeats: bool
    partition_signal: bool
    split_brain_signal: bool
    leader_id: str
    generated_at: float

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

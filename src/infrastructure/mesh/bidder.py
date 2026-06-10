"""
Cyber Security Test Pipeline - Neural-Mesh Task Bidder
Implements a game-theory approach to distributed task allocation.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from src.infrastructure.mesh.manifest import discover_manifest

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

DEFAULT_CROSS_REGION_PENALTY = float(os.getenv("MESH_CROSS_REGION_PENALTY", "0.15"))
# Bandwidth below this threshold (Mbps) is treated as a bottleneck and
# adds a penalty proportional to the deficit.
DEFAULT_MIN_BANDWIDTH_MBPS = float(os.getenv("MESH_MIN_BANDWIDTH_MBPS", "50"))
DEFAULT_LOW_BANDWIDTH_PENALTY = float(os.getenv("MESH_LOW_BANDWIDTH_PENALTY", "0.10"))


def _normalize_caps(caps: Any) -> list[str]:
    """Coerce a capability-like value into a deduplicated lowercase list."""
    if caps is None:
        return []
    if isinstance(caps, str):
        items = [caps]
    elif isinstance(caps, (list, tuple, set, frozenset)):
        items = list(caps)
    else:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        if not isinstance(raw, str):
            continue
        normalized = raw.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


class MeshBidder:
    """
    Self-Aware Task Bidding System.
    Calculates a 'Work Score' based on local hardware telemetry.
    The mesh uses these bids to assign tasks to the most optimal node.

    The bidder no longer hard-codes its capability list; ``local_capabilities``
    is either supplied by the caller (typically from
    ``MeshNode.capabilities`` so remote workers can score correctly for
    a node) or auto-discovered via
    :func:`src.infrastructure.mesh.manifest.discover_manifest`.
    """

    def __init__(
        self,
        node_id: str,
        local_capabilities: list[str] | None = None,
        *,
        local_region: str | None = None,
        cross_region_penalty: float = DEFAULT_CROSS_REGION_PENALTY,
        min_bandwidth_mbps: float = DEFAULT_MIN_BANDWIDTH_MBPS,
        low_bandwidth_penalty: float = DEFAULT_LOW_BANDWIDTH_PENALTY,
    ) -> None:
        self.node_id = node_id
        if local_capabilities is None:
            local_capabilities = list(discover_manifest().capabilities)
        self.local_capabilities = _normalize_caps(local_capabilities)
        if local_region is None:
            local_region = (
                os.getenv("MESH_REGION") or os.getenv("REGION") or discover_manifest().region
            )
        self.local_region = str(local_region or "")
        self.cross_region_penalty = max(0.0, float(cross_region_penalty))
        self.min_bandwidth_mbps = max(0.0, float(min_bandwidth_mbps))
        self.low_bandwidth_penalty = max(0.0, float(low_bandwidth_penalty))

    def _calculate_hardware_score(self, metrics: dict[str, Any] | None = None) -> float:
        """Calculate hardware suitability score."""
        if metrics:
            cpu_free = 100.0 - float(metrics.get("cpu_usage", 50.0))
            ram_mb = float(metrics.get("ram_available_mb", 1024.0))
            # Normalize RAM to a percentage (assume 8GB is 100% for bidding purposes)
            ram_free_pct = min(100.0, (ram_mb / 8192.0) * 100.0)
        elif psutil:
            try:
                cpu_free = 100.0 - psutil.cpu_percent(interval=0.1)
                ram_free_pct = (
                    psutil.virtual_memory().available / psutil.virtual_memory().total * 100
                )
            except Exception:
                cpu_free = 50.0
                ram_free_pct = 50.0
        else:
            cpu_free = 50.0
            ram_free_pct = 50.0

        return (cpu_free * 0.6 + ram_free_pct * 0.4) / 100.0

    def _calculate_affinity_score(
        self,
        task_metadata: dict[str, Any],
        local_caps_override: list[str] | None = None,
    ) -> float:
        """Calculate task capability affinity score.

        ``local_caps_override`` lets callers (e.g. the balancer when scoring
        a remote node from gossiped data) supply the *peer* node's
        published capabilities instead of this bidder's local view.
        """
        required = _normalize_caps(task_metadata.get("required_capabilities", []))
        if not required:
            return 1.0
        local_caps = (
            _normalize_caps(local_caps_override)
            if local_caps_override is not None
            else self.local_capabilities
        )
        if not local_caps:
            return 0.0
        local_set = set(local_caps)
        matches = sum(1 for c in required if c in local_set)
        return matches / len(required)

    def _calculate_pressure_penalty(self) -> float:
        """Calculate queue and CPU load pressure penalty."""
        if psutil:
            try:
                # getloadavg is Unix-only
                load_avg_getter = getattr(psutil, "getloadavg", None)
                if callable(load_avg_getter):
                    load_avg = load_avg_getter()[0]
                else:
                    # Fallback for Windows: prime the counter (interval=None
                    # is non-blocking after the first call) and use the
                    # last reading. ``psutil.cpu_percent()`` without an
                    # interval sleeps for a full second on first call, so
                    # we explicitly prime here.
                    psutil.cpu_percent(interval=None)
                    load_avg = psutil.cpu_percent(interval=None) / 100.0 * (psutil.cpu_count() or 1)

                return float(min(1.0, load_avg / (psutil.cpu_count() or 1)))
            except Exception:
                return 0.5
        else:
            return 0.5

    def calculate_bid(
        self,
        task_metadata: dict[str, Any],
        metrics: dict[str, Any] | None = None,
        local_capabilities: list[str] | None = None,
        *,
        peer_region: str | None = None,
        peer_bandwidth_mbps: float | None = None,
    ) -> float:
        """
        Calculate a bid score (0.0 - 1.0). Higher is better (more capable).

        Args:
            task_metadata: Requirements of the task.
            metrics: Optional override for hardware metrics (used for remote estimation).
            local_capabilities: Override the capability set used for affinity
                scoring (used when the balancer is estimating a remote
                node's bid from gossiped manifest data).
            peer_region: Region of the peer being scored (None = same as self).
            peer_bandwidth_mbps: Bandwidth advertised by the peer.  When
                below :attr:`min_bandwidth_mbps` a small penalty is
                applied to keep traffic on well-connected nodes.
        """
        hardware_score = self._calculate_hardware_score(metrics)
        affinity_score = self._calculate_affinity_score(
            task_metadata, local_caps_override=local_capabilities
        )
        pressure_penalty = self._calculate_pressure_penalty()

        # Geographic + capacity penalty (region / bandwidth).
        # Both penalties are bounded in [0, 0.2] so a remote node can
        # still out-bid a local one when the local hardware is bad.
        region_penalty = 0.0
        if peer_region and self.local_region and peer_region != self.local_region:
            region_penalty = self.cross_region_penalty
        bandwidth_penalty = 0.0
        if peer_bandwidth_mbps is not None and peer_bandwidth_mbps < self.min_bandwidth_mbps:
            deficit = max(
                0.0, (self.min_bandwidth_mbps - peer_bandwidth_mbps) / self.min_bandwidth_mbps
            )
            bandwidth_penalty = min(
                self.low_bandwidth_penalty, deficit * self.low_bandwidth_penalty
            )

        # Final Frontier Bid
        final_bid: float = (
            (hardware_score * 0.5)
            + (affinity_score * 0.3)
            - (pressure_penalty * 0.2)
            - (region_penalty * 0.5)
            - (bandwidth_penalty * 0.3)
        )

        return float(round(max(0.01, final_bid), 4))

    async def submit_bid(self, job_id: str, bid_value: float, redis_client: Any) -> None:
        """Submit the bid to the mesh for the given job."""
        bid_key = f"cyber:bids:{job_id}"
        try:
            # Atomic HSET for the bid
            await redis_client.hset(bid_key, self.node_id, bid_value)
            # Set TTL so dead job bids don't persist
            await redis_client.expire(bid_key, 60)
            logger.info("Submitted bid %.4f for job %s", bid_value, job_id)
        except Exception as e:
            logger.error("Bid submission failed: %s", e)


def find_winning_bid(bids: dict[str, str]) -> str | None:
    """Find the worker ID with the highest bid."""
    if not bids:
        return None

    try:
        # Sort by value (bids are stored as strings in Redis HASH)
        sorted_bids = sorted(bids.items(), key=lambda x: float(x[1]), reverse=True)
        winner_id, winner_val = sorted_bids[0]
        logger.info("Bid Winner: %s (Score: %s)", winner_id, winner_val)
        return winner_id
    except (ValueError, TypeError):
        return None

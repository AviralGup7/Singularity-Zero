"""
Cyber Security Test Pipeline - Neural-Mesh Task Bidder
Implements a game-theory approach to distributed task allocation.
"""

from __future__ import annotations

import logging
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)


class MeshBidder:
    """
    Self-Aware Task Bidding System.
    Calculates a 'Work Score' based on local hardware telemetry.
    The mesh uses these bids to assign tasks to the most optimal node.
    """

    def __init__(self, node_id: str):
        self.node_id = node_id

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

    def _calculate_affinity_score(self, task_metadata: dict[str, Any]) -> float:
        """Calculate task capability affinity score."""
        capabilities = task_metadata.get("required_capabilities", [])
        local_caps = ["browser", "nuclei", "semgrep"]  # Inferred local caps

        matches = sum(1 for c in capabilities if c in local_caps)
        return matches / max(len(capabilities), 1)

    def _calculate_pressure_penalty(self) -> float:
        """Calculate queue and CPU load pressure penalty."""
        if psutil:
            try:
                # getloadavg is Unix-only
                if hasattr(psutil, "getloadavg"):
                    load_avg = psutil.getloadavg()[0]
                else:
                    # Fallback for Windows
                    load_avg = psutil.cpu_percent() / 100.0 * (psutil.cpu_count() or 1)

                return min(1.0, load_avg / (psutil.cpu_count() or 1))
            except Exception:
                return 0.5
        else:
            return 0.5

    def calculate_bid(
        self, task_metadata: dict[str, Any], metrics: dict[str, Any] | None = None
    ) -> float:
        """
        Calculate a bid score (0.0 - 1.0). Higher is better (more capable).

        Args:
            task_metadata: Requirements of the task.
            metrics: Optional override for hardware metrics (used for remote estimation).
        """
        hardware_score = self._calculate_hardware_score(metrics)
        affinity_score = self._calculate_affinity_score(task_metadata)
        pressure_penalty = self._calculate_pressure_penalty()

        # Final Frontier Bid
        final_bid: float = (
            (hardware_score * 0.5) + (affinity_score * 0.3) - (pressure_penalty * 0.2)
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

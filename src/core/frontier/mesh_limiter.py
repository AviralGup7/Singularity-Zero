"""
Cyber Security Test Pipeline - Mesh-Wide Rate Limiter
Synchronizes request budgets across the entire distributed mesh.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

class MeshRateLimiter:
    """
    Frontier Global Limiter.
    Ensures that a target is not overwhelmed by the collective power of the mesh.
    Divided budgets are calculated dynamically based on the number of active workers.
    """
    def __init__(self, global_rps_limit: float = 50.0) -> None:
        self.global_rps_limit = global_rps_limit
        self._local_budget = global_rps_limit
        self._last_calc = time.time()
        self._tokens = global_rps_limit
        self._lock = asyncio.Lock()

    def update_mesh_size(self, active_worker_count: int) -> None:
        """Re-calculate the local share of the global budget."""
        count = max(1, active_worker_count)
        self._local_budget = self.global_rps_limit / count
        logger.info("Mesh Limiter: Local budget updated to %.2f RPS (Mesh Size: %d)", 
                    self._local_budget, count)

    async def acquire(self) -> None:
        """Token bucket acquisition with micro-sleep backpressure."""
        while True:
            async with self._lock:
                # Refill tokens based on local budget
                now = time.time()
                elapsed = now - self._last_calc
                self._tokens = min(self._local_budget, self._tokens + (elapsed * self._local_budget))
                self._last_calc = now
                
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                
                # If not enough tokens, calculate wait time
                wait_time = (1.0 - self._tokens) / self._local_budget

            # Sleep OUTSIDE the lock to allow other coroutines to progress or update mesh size
            await asyncio.sleep(wait_time)

    def get_stats(self) -> dict[str, Any]:
        return {
            "global_limit": self.global_rps_limit,
            "local_share": round(self._local_budget, 2),
            "current_tokens": round(self._tokens, 2)
        }

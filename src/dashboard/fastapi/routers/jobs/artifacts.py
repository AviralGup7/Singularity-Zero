"""Shared cache and constants for SSE job streaming endpoints."""

import asyncio
import logging
import time
from typing import Any, cast

from src.dashboard.feature_flags import FeatureFlags

logger = logging.getLogger(__name__)

# Job stall detection threshold in seconds
STALLED_THRESHOLD_SECONDS = FeatureFlags.STALLED_THRESHOLD_SECONDS()

# Simple cache: job_id -> (timestamp, job_dict)
_JOB_CACHE: dict[str, tuple[float, dict[str, Any] | None]] = {}
_JOB_CACHE_LOCK = asyncio.Lock()


async def get_cached_job(job_id: str, services: Any) -> dict[str, Any] | None:
    async with _JOB_CACHE_LOCK:
        now = time.time()
        if job_id in _JOB_CACHE:
            ts, cached_job = _JOB_CACHE[job_id]
            is_terminal = cached_job and cached_job.get("status") in (
                "completed",
                "failed",
                "stopped",
            )
            if is_terminal or (now - ts < 0.5):
                return cached_job
        job = await asyncio.to_thread(services.get_job, job_id)
        _JOB_CACHE[job_id] = (now, job)
        return cast(dict[str, Any] | None, job)

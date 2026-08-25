"""Re-export shim for the jobs/sse module.

The original monolithic sse.py has been deconstructed into single-concern
files under jobs/ (artifacts, sse_streaming, job_lifecycle). This module
preserves backward compatibility by re-exporting the relevant routers and
handlers so that existing imports such as ``from jobs.sse import router``
continue to work.
"""

from fastapi import APIRouter

from src.dashboard.fastapi.routers.jobs.artifacts import (
    get_cached_job as get_cached_job,
)
from src.dashboard.fastapi.routers.jobs.job_lifecycle import (
    router as job_lifecycle_router,
)
from src.dashboard.fastapi.routers.jobs.job_lifecycle import (
    stream_job_progress as stream_job_progress,
)
from src.dashboard.fastapi.routers.jobs.sse_streaming import (
    router as sse_streaming_router,
)
from src.dashboard.fastapi.routers.jobs.sse_streaming import (
    stream_job_logs as stream_job_logs,
)

router = APIRouter()
router.include_router(sse_streaming_router)
router.include_router(job_lifecycle_router)

__all__ = [
    "router",
    "stream_job_logs",
    "stream_job_progress",
    "get_cached_job",
]

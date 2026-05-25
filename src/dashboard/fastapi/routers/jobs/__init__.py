"""Jobs sub-router aggregation and mounting.

This package deconstructs the jobs router into single-concern files while
re-exporting all endpoint functions to preserve seamless backward compatibility.
"""

from fastapi import APIRouter

from .detail import get_job as get_job
from .detail import router as detail_router
from .historical_durations import get_historical_durations as get_historical_durations
from .historical_durations import router as durations_router
from .list import list_jobs as list_jobs
from .list import router as list_router
from .logs import get_job_logs as get_job_logs
from .logs import router as logs_router
from .remediation import get_job_remediation as get_job_remediation
from .remediation import router as remediation_router
from .restart import restart_job_safe as restart_job_safe
from .restart import router as restart_router
from .sse import router as sse_router
from .sse import stream_job_logs as stream_job_logs
from .sse import stream_job_progress as stream_job_progress
from .start import router as start_router
from .start import start_job as start_job
from .stop import router as stop_router
from .stop import stop_job as stop_job
from .timeline import get_job_timeline as get_job_timeline
from .timeline import router as timeline_router
from .trace import get_job_trace_link as get_job_trace_link
from .trace import router as trace_router

router = APIRouter()

# Register deconstructed sub-routers sequentially
router.include_router(list_router)
router.include_router(durations_router)
router.include_router(detail_router)
router.include_router(trace_router)
router.include_router(remediation_router)
router.include_router(logs_router)
router.include_router(sse_router)
router.include_router(start_router)
router.include_router(stop_router)
router.include_router(restart_router)
router.include_router(timeline_router)

__all__ = [
    "router",
    "list_jobs",
    "get_historical_durations",
    "get_job",
    "get_job_trace_link",
    "get_job_remediation",
    "get_job_logs",
    "stream_job_logs",
    "stream_job_progress",
    "start_job",
    "stop_job",
    "restart_job_safe",
    "get_job_timeline",
]

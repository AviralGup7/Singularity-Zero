"""Shared utility functions for dashboard API routers."""

import logging
from typing import Any, cast

from fastapi import HTTPException

from src.dashboard.feature_flags import FeatureFlags

logger = logging.getLogger(__name__)


def snapshot_job_api(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a stable snapshot of a job for API responses.

    Avoids re-snapshotting payloads that already contain live timing
    fields (started_at_label, elapsed_seconds, stage_progress),
    which prevents false "stalled" states from stale computed values.

    Args:
        raw: Raw job dictionary from the job store.

    Returns:
        Snapshot dict safe for API serialization.
    """
    if (
        isinstance(raw, dict)
        and "started_at_label" in raw
        and "elapsed_seconds" in raw
        and "stage_progress" in raw
    ):
        return raw

    from src.dashboard.job_state import snapshot_job

    return snapshot_job(raw)


def current_stage_entry(job: dict[str, Any]) -> dict[str, Any] | None:
    """Extract progress metadata for the current running stage."""
    stage_name = str(job.get("stage", "")).strip()
    stage_progress = job.get("stage_progress")
    if isinstance(stage_progress, dict) and stage_name:
        entry = stage_progress.get(stage_name)
        if isinstance(entry, dict):
            return entry
    if isinstance(stage_progress, list) and stage_name:
        for entry in stage_progress:
            if isinstance(entry, dict) and str(entry.get("stage", "")).strip() == stage_name:
                return entry
    return None


def current_stage_percent(job: dict[str, Any], stage_entry: dict[str, Any] | None) -> int:
    """Calculate the completion percentage of the current stage."""
    if isinstance(stage_entry, dict):
        from_entry = stage_entry.get("percent")
        if isinstance(from_entry, (int, float)):
            return max(0, min(100, int(from_entry)))
    processed = job.get("stage_processed")
    total = job.get("stage_total")
    if isinstance(processed, (int, float)) and isinstance(total, (int, float)) and total > 0:
        return max(0, min(100, int((processed / total) * 100)))
    return 0


def heartbeat_interval_seconds() -> float:
    """Resolve heartbeat interval defensively from feature flags.

    Supports both callable and scalar style values so runtime patching
    cannot crash SSE loops with type errors.
    """
    raw_value = getattr(FeatureFlags, "SSE_HEARTBEAT_INTERVAL_SECONDS", 25)
    interval = raw_value() if callable(raw_value) else raw_value
    try:
        parsed = float(interval)
    except (TypeError, ValueError):
        parsed = 25.0
    return max(5.0, parsed)


from pathlib import Path

from src.dashboard.fastapi.validation import validate_target_name


# ...
def get_safe_target_dir(output_root: Path, target_name: str) -> Path:
    """Validate target name and ensure directory exists within output_root. (SEC-FIX)"""
    if not validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    # Use .resolve() to flatten path and verify boundary
    output_root_resolved = output_root.resolve()
    target_dir = (output_root_resolved / target_name).resolve()

    if not target_dir.is_relative_to(output_root_resolved):
        logger.warning(
            "Security: Attempted directory traversal detected for target_name: %r", target_name
        )
        raise HTTPException(status_code=404, detail="Target not found")

    if not target_dir.exists():
        # Check for case-insensitive match among existing child directories
        for entry in output_root_resolved.iterdir():
            if entry.is_dir() and entry.name.lower() == target_name.lower():
                return entry
        raise HTTPException(status_code=404, detail="Target not found")

    return target_dir


def get_safe_target_path(output_root: Path, target_name: str) -> Path:
    """Construct a safe target path within output_root, without requiring existence. (SEC-FIX)"""
    if not validate_target_name(target_name):
        raise HTTPException(status_code=400, detail="Invalid target name")

    # Use .resolve() to flatten path and verify boundary
    output_root_resolved = output_root.resolve()
    target_path = (output_root_resolved / target_name).resolve()

    if not target_path.is_relative_to(output_root_resolved):
        logger.warning(
            "Security: Attempted directory traversal detected (path) for target_name: %r",
            target_name,
        )
        raise HTTPException(status_code=403, detail="Target path out of bounds")

    return target_path


async def get_enriched_job(job_id: str, services: Any) -> dict[str, Any]:
    """Retrieve and validate job presence in the job queue store."""
    job = services.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return cast(dict[str, Any], job)


def job_target_name(job: dict[str, Any] | None) -> str:
    """Return the canonical target identifier for a job, or '' if missing.

    The dashboard stores the target under several different keys depending
    on the job source (``target_name``, ``hostname``, ``target``). All
    job routers funnel through this helper so the tenant boundary check
    in :func:`is_target_owned_by_tenant` always sees the same value.
    """
    if not isinstance(job, dict):
        return ""
    return str(job.get("target_name") or job.get("hostname") or job.get("target") or "")

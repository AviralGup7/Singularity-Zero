"""Job state management for pipeline run tracking.

Provides functions for applying progress updates, managing job state
transitions, and persisting job snapshots with progress history.
"""

import time  # noqa: F401

from src.dashboard.job_snapshot import (
    _snapshot_progress_telemetry,
    snapshot_job,
)
from src.dashboard.job_state_helpers import (
    STALLED_AFTER_SECONDS,
    _apply_terminal_state,
    _coerce_epoch,
    _coerce_float,
    _coerce_int,
    _event_texts,
    _finalize_stage,
    _get_active_stages,
    _increment_state_version,
    _mark_stage_done,
    _mark_stage_running,
    _normalize_stage_status,
    _stage_progress_label,
    append_log,
)
from src.dashboard.progress_ingestion import (
    _append_progress_history,
    _ensure_progress_telemetry,
    _infer_percent,
    _infer_stage_percent,
    _merge_progress_telemetry,
    _record_stage_transition,
    _stage_running_count,
    apply_progress,
)

# Re-exporting these so that any import from job_state.py works transparently.
__all__ = [
    "STALLED_AFTER_SECONDS",
    "_apply_terminal_state",
    "_coerce_epoch",
    "_coerce_float",
    "_coerce_int",
    "_event_texts",
    "_finalize_stage",
    "_get_active_stages",
    "_increment_state_version",
    "_mark_stage_done",
    "_mark_stage_running",
    "_normalize_stage_status",
    "_stage_progress_label",
    "append_log",
    "_append_progress_history",
    "_ensure_progress_telemetry",
    "_infer_percent",
    "_infer_stage_percent",
    "_merge_progress_telemetry",
    "_record_stage_transition",
    "_stage_running_count",
    "apply_progress",
    "_snapshot_progress_telemetry",
    "snapshot_job",
]

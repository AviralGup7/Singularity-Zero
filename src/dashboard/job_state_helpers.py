"""Helper functions and type coercions for job state management."""

import logging
import time
from datetime import datetime
from typing import Any

from src.dashboard.registry import STAGE_LABELS
from src.dashboard.scope_utils import estimate_remaining
from src.pipeline.constants.progress import STAGE_BASELINE_PERCENT

logger = logging.getLogger(__name__)

STALLED_AFTER_SECONDS = 75
PROGRESS_HISTORY_LIMIT = 80
TRANSITION_HISTORY_LIMIT = 40
EVENT_LOG_LIMIT = 24
LOG_RETENTION_LIMIT = 20


def _coerce_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _coerce_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except (TypeError, ValueError):
            return None
    return None


def _normalize_stage_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if status in {"error", "failed", "timeout"}:
        return "error"
    if status in {"skipped", "skip"}:
        return "skipped"
    if status in {"completed", "done", "success"}:
        return "completed"
    if status == "pending":
        return "pending"
    return "running"


def _coerce_epoch(value: object, fallback: float) -> float:
    if value is None:
        return fallback
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return fallback
        try:
            return float(text)
        except ValueError:
            try:
                return datetime.fromisoformat(text).timestamp()
            except ValueError:
                return fallback
    return fallback


def _event_texts(value: object) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            text = str(item or "").strip()
            if text:
                out.append(text)
        return out
    return []


def _stage_progress_label(job: dict[str, Any]) -> str:
    processed = job.get("stage_processed")
    total = job.get("stage_total")
    if isinstance(processed, int) and isinstance(total, int) and total > 0:
        return f"{processed}/{total}"
    return ""


def _get_active_stages(job: dict[str, Any]) -> set[str]:
    """Get the active stages set, migrating legacy list data if needed."""
    raw = job.get("_active_stages")
    if isinstance(raw, set):
        return raw
    if isinstance(raw, list):
        # Migrate legacy list to set
        result = set(raw)
        job["_active_stages"] = result
        return result
    result = set()
    job["_active_stages"] = result
    return result


def _mark_stage_running(job: dict[str, Any], stage: str) -> None:
    active_stages = _get_active_stages(job)
    active_stages.add(stage)
    best = max(active_stages, key=lambda s: STAGE_BASELINE_PERCENT.get(s, 0))
    job["stage"] = best
    job["stage_label"] = STAGE_LABELS.get(best, best.replace("_", " ").title())


def _mark_stage_done(job: dict[str, Any], stage: str) -> None:
    active_stages = _get_active_stages(job)
    active_stages.discard(stage)
    if active_stages:
        best = max(active_stages, key=lambda s: STAGE_BASELINE_PERCENT.get(s, 0))
        job["stage"] = best
        job["stage_label"] = STAGE_LABELS.get(best, best.replace("_", " ").title())


def append_log(job: dict[str, Any], line: str) -> None:
    clean = line.strip()
    if not clean:
        return
    if job.get("latest_logs") is None:
        job["latest_logs"] = []
    if job["latest_logs"] and job["latest_logs"][-1] == clean:
        return
    job["latest_logs"].append(clean)
    job["latest_logs"] = job["latest_logs"][-LOG_RETENTION_LIMIT:]
    job["updated_at"] = time.time()


def _increment_state_version(job: dict[str, Any]) -> int:
    current = int(job.get("state_version", 0) or 0)
    new_version = current + 1
    job["state_version"] = new_version
    return new_version


def _compute_eta_fallback(job: dict[str, Any], elapsed_seconds: float) -> float | None:
    return estimate_remaining(
        job.get("progress_percent", 0),
        elapsed_seconds,
        progress_history=list(job.get("progress_history", [])),
    )


def _compute_eta_bayesian(job: dict[str, Any], elapsed_seconds: float) -> float | None:
    try:
        from src.dashboard.eta_engine import get_eta_engine

        eta_engine = get_eta_engine()
        eta_result = eta_engine.compute_eta_sync(
            job_id=job.get("id", ""),
            stage=job.get("stage", ""),
            elapsed=elapsed_seconds,
        )
        if eta_result:
            return eta_result.get("eta_seconds")
    except Exception:
        logger.debug("Bayesian ETA engine unavailable, falling back")
    return _compute_eta_fallback(job, elapsed_seconds)


def _finalize_stage(job: dict[str, Any], stage: str) -> None:
    now = time.time()
    stage_progress: dict[str, dict[str, Any]] = job.setdefault("stage_progress", {})
    if stage in stage_progress:
        stage_progress[stage]["status"] = "completed"
        if int(stage_progress[stage].get("percent", 0) or 0) < 100:
            stage_progress[stage]["percent"] = 100
        stage_progress[stage]["updated_at"] = now
    _mark_stage_done(job, stage)


def _apply_terminal_state(
    job: dict[str, Any],
    status: str,
    error: str | None = None,
    returncode: int | None = None,
) -> None:
    now = time.time()
    _increment_state_version(job)
    job["status"] = status
    job["finished_at"] = now
    if error:
        job["error"] = error
    if returncode is not None:
        job["returncode"] = returncode

    stage_progress: dict[str, dict[str, Any]] = job.setdefault("stage_progress", {})
    for sp in stage_progress.values():
        if sp.get("status") == "running":
            sp["status"] = "completed"
            sp["updated_at"] = now

    active_stages = _get_active_stages(job)
    active_stages.clear()

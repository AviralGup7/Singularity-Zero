"""Job state management for pipeline run tracking.

Provides functions for applying progress updates, managing job state
transitions, and persisting job snapshots with progress history.
"""

import logging
import time
from datetime import UTC, datetime
from typing import Any

from src.dashboard.registry import STAGE_LABELS
from src.dashboard.utils import estimate_remaining, format_duration, format_epoch_ist

logger = logging.getLogger(__name__)

STALLED_AFTER_SECONDS = 75
PROGRESS_HISTORY_LIMIT = 80
TRANSITION_HISTORY_LIMIT = 40
EVENT_LOG_LIMIT = 24
STAGE_BASELINE_PERCENT = {
    "startup": 2,
    "subdomains": 12,
    "live_hosts": 30,
    "urls": 50,
    "parameters": 62,
    "ranking": 74,
    "priority": 78,
    "passive_scan": 86,
    "active_scan": 88,
    "nuclei": 90,
    "access_control": 92,
    "validation": 94,
    "intelligence": 96,
    "reporting": 98,
    "completed": 100,
    # Aliases for backward compatibility
    "analysis": 86,
}


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


def _infer_percent(job: dict[str, Any], stage: str, payload: dict[str, Any]) -> int:
    current = int(job.get("progress_percent", 0) or 0)
    explicit = _coerce_int(payload.get("percent"))
    if explicit is not None:
        return max(0, min(100, explicit))

    stage_percent = _coerce_int(payload.get("stage_percent"))
    processed = _coerce_int(payload.get("processed"))
    total = _coerce_int(payload.get("total"))

    if stage_percent is None and processed is not None and total and total > 0:
        stage_percent = int((processed / total) * 100)

    if stage_percent is None:
        return current

    stage_percent = max(0, min(100, stage_percent))
    current_base = STAGE_BASELINE_PERCENT.get(stage, current)
    next_base = 100
    for name, candidate in STAGE_BASELINE_PERCENT.items():
        if candidate > current_base:
            next_base = min(next_base, candidate)

    stage_span = max(1, next_base - current_base)
    inferred = current_base + int((stage_percent / 100) * stage_span)
    return max(0, min(100, inferred))


def _infer_stage_percent(stage: str, payload: dict[str, Any], current_percent: int) -> int:
    stage_percent = _coerce_int(payload.get("stage_percent"))
    if stage_percent is not None:
        # Prefer explicit stage-local progress, even if it corrects prior estimates.
        return max(0, min(100, stage_percent))

    processed = _coerce_int(payload.get("processed"))
    total = _coerce_int(payload.get("total"))
    if processed is not None and total and total > 0:
        derived = int((max(0, processed) / total) * 100)
        # Prefer concrete processed/total progress over baseline inference.
        return max(0, min(100, derived))

    explicit_overall = _coerce_int(payload.get("percent"))
    base = STAGE_BASELINE_PERCENT.get(stage)
    if explicit_overall is None or base is None:
        return current_percent

    next_base = 100
    for _, candidate in STAGE_BASELINE_PERCENT.items():
        if candidate > base:
            next_base = min(next_base, candidate)
    span = max(1, next_base - base)
    relative = int(((explicit_overall - base) / span) * 100)
    return max(current_percent, max(0, min(100, relative)))


def _append_progress_history(job: dict[str, Any], timestamp: float) -> None:
    history = job.setdefault("progress_history", [])
    percent = int(job.get("progress_percent", 0) or 0)
    if history and history[-1][1] == percent and (timestamp - history[-1][0]) < 3:
        return
    history.append((timestamp, percent))
    if len(history) > PROGRESS_HISTORY_LIMIT:
        del history[:-PROGRESS_HISTORY_LIMIT]


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


def _ensure_progress_telemetry(job: dict[str, Any]) -> dict[str, Any]:
    telemetry = job.get("progress_telemetry")
    if not isinstance(telemetry, dict):
        telemetry = {}
        job["progress_telemetry"] = telemetry
    telemetry.setdefault("active_task_count", 0)
    telemetry.setdefault("retry_count", 0)
    telemetry.setdefault("failure_count", 0)
    telemetry.setdefault("targets", {"queued": 0, "scanning": 0, "done": 0})
    telemetry.setdefault("stage_transitions", [])
    telemetry.setdefault("event_triggers", [])
    telemetry.setdefault("skipped_stages", [])
    telemetry.setdefault("top_active_targets", [])
    return telemetry


def _stage_running_count(job: dict[str, Any]) -> int:
    stage_progress = job.get("stage_progress")
    if not isinstance(stage_progress, dict):
        return 0
    return len(
        [
            stage
            for stage in stage_progress.values()
            if isinstance(stage, dict) and stage.get("status") == "running"
        ]
    )


def _record_stage_transition(
    job: dict[str, Any],
    *,
    stage: str,
    status: str,
    now: float,
    message: str = "",
) -> None:
    telemetry = _ensure_progress_telemetry(job)
    transitions = telemetry.setdefault("stage_transitions", [])
    if not isinstance(transitions, list):
        transitions = []
        telemetry["stage_transitions"] = transitions
    if transitions:
        previous = transitions[-1]
        if (
            isinstance(previous, dict)
            and previous.get("stage") == stage
            and previous.get("status") == status
        ):
            previous["timestamp"] = now
            if message:
                previous["message"] = message
            return
    transitions.append(
        {
            "stage": stage,
            "status": status,
            "timestamp": now,
            "message": message,
        }
    )
    if len(transitions) > TRANSITION_HISTORY_LIMIT:
        del transitions[:-TRANSITION_HISTORY_LIMIT]


def _merge_progress_telemetry(
    job: dict[str, Any],
    *,
    payload: dict[str, Any],
    stage: str,
    stage_status: str,
    now: float,
) -> None:
    telemetry = _ensure_progress_telemetry(job)
    details = payload.get("details")
    details_map = details if isinstance(details, dict) else {}

    active_count = (
        _coerce_int(payload.get("active_task_count"))
        or _coerce_int(payload.get("active_tasks"))
        or _coerce_int(payload.get("workers_running"))
        or _coerce_int(payload.get("concurrency"))
        or _coerce_int(details_map.get("concurrency"))
    )
    if active_count is None:
        active_count = _stage_running_count(job)
    telemetry["active_task_count"] = max(0, active_count)

    requests_per_second = (
        _coerce_float(payload.get("requests_per_second"))
        or _coerce_float(payload.get("req_per_sec"))
        or _coerce_float(payload.get("rps"))
        or _coerce_float(details_map.get("requests_per_second"))
    )
    if requests_per_second is not None:
        telemetry["requests_per_second"] = max(0.0, round(requests_per_second, 2))

    throughput = (
        _coerce_float(payload.get("throughput_per_second"))
        or _coerce_float(payload.get("throughput"))
        or _coerce_float(payload.get("items_per_second"))
        or _coerce_float(details_map.get("throughput_per_second"))
    )
    if throughput is not None:
        telemetry["throughput_per_second"] = max(0.0, round(throughput, 2))

    eta_seconds = (
        _coerce_float(payload.get("eta_seconds"))
        or _coerce_float(payload.get("remaining_seconds"))
        or _coerce_float(details_map.get("eta_seconds"))
    )
    if eta_seconds is not None:
        telemetry["eta_seconds"] = max(0.0, round(eta_seconds, 1))

    high_value_count = (
        _coerce_int(payload.get("high_value_target_count"))
        or _coerce_int(payload.get("high_value_targets"))
        or _coerce_int(payload.get("interesting_target_count"))
        or _coerce_int(details_map.get("high_value_target_count"))
    )
    if high_value_count is not None:
        telemetry["high_value_target_count"] = max(0, high_value_count)

    vuln_likelihood = (
        _coerce_float(payload.get("vulnerability_likelihood_score"))
        or _coerce_float(payload.get("vuln_likelihood_score"))
        or _coerce_float(details_map.get("vulnerability_likelihood_score"))
    )
    if vuln_likelihood is not None:
        telemetry["vulnerability_likelihood_score"] = max(0.0, min(1.0, vuln_likelihood))

    signal_noise_ratio = _coerce_float(payload.get("signal_noise_ratio")) or _coerce_float(
        details_map.get("signal_noise_ratio")
    )
    if signal_noise_ratio is not None:
        telemetry["signal_noise_ratio"] = max(0.0, round(signal_noise_ratio, 3))

    confidence_score = _coerce_float(payload.get("confidence_score")) or _coerce_float(
        details_map.get("confidence_score")
    )
    if confidence_score is not None:
        telemetry["confidence_score"] = max(0.0, min(1.0, confidence_score))

    top_targets = payload.get("top_active_targets")
    if isinstance(top_targets, list):
        telemetry["top_active_targets"] = [
            str(entry).strip() for entry in top_targets if str(entry).strip()
        ][:10]

    next_best_action = str(
        payload.get("next_best_action") or details_map.get("next_best_action") or ""
    ).strip()
    if next_best_action:
        telemetry["next_best_action"] = next_best_action

    bottleneck_stage = str(
        payload.get("bottleneck_stage") or details_map.get("bottleneck_stage") or ""
    ).strip()
    if bottleneck_stage:
        telemetry["bottleneck_stage"] = bottleneck_stage
    bottleneck_seconds = _coerce_float(payload.get("bottleneck_seconds")) or _coerce_float(
        details_map.get("bottleneck_seconds")
    )
    if bottleneck_seconds is not None:
        telemetry["bottleneck_seconds"] = max(0.0, round(bottleneck_seconds, 1))

    dedup_removed = (
        _coerce_int(payload.get("dedup_removed"))
        or _coerce_int(details_map.get("dedup_removed"))
        or _coerce_int(details_map.get("removed"))
    )
    dedup_remaining = (
        _coerce_int(payload.get("dedup_remaining"))
        or _coerce_int(details_map.get("dedup_remaining"))
        or _coerce_int(details_map.get("remaining"))
    )
    if dedup_removed is not None or dedup_remaining is not None:
        telemetry["deduplication"] = {
            "removed": max(0, dedup_removed or 0),
            "remaining": max(0, dedup_remaining or 0),
        }

    targets = telemetry.setdefault("targets", {"queued": 0, "scanning": 0, "done": 0})
    if isinstance(targets, dict):
        queued = _coerce_int(payload.get("targets_queued")) or _coerce_int(
            details_map.get("targets_queued")
        )
        scanning = _coerce_int(payload.get("targets_scanning")) or _coerce_int(
            details_map.get("targets_scanning")
        )
        done = _coerce_int(payload.get("targets_done")) or _coerce_int(
            details_map.get("targets_done")
        )
        if queued is not None:
            targets["queued"] = max(0, queued)
        if scanning is not None:
            targets["scanning"] = max(0, scanning)
        if done is not None:
            targets["done"] = max(0, done)

    drop_input = (
        _coerce_int(payload.get("drop_off_input"))
        or _coerce_int(details_map.get("drop_off_input"))
        or _coerce_int(details_map.get("input_count"))
    )
    drop_kept = (
        _coerce_int(payload.get("drop_off_kept"))
        or _coerce_int(details_map.get("drop_off_kept"))
        or _coerce_int(details_map.get("kept_count"))
    )
    drop_dropped = (
        _coerce_int(payload.get("drop_off_dropped"))
        or _coerce_int(details_map.get("drop_off_dropped"))
        or _coerce_int(details_map.get("dropped_count"))
    )
    if drop_input is not None or drop_kept is not None or drop_dropped is not None:
        resolved_input = max(0, drop_input or 0)
        resolved_kept = max(0, drop_kept or 0)
        resolved_dropped = (
            max(0, drop_dropped)
            if drop_dropped is not None
            else max(0, resolved_input - resolved_kept)
        )
        telemetry["drop_off"] = {
            "input": resolved_input,
            "kept": resolved_kept,
            "dropped": resolved_dropped,
        }

    event_texts = []
    event_texts.extend(_event_texts(payload.get("event_trigger")))
    event_texts.extend(_event_texts(payload.get("event_triggers")))
    event_texts.extend(_event_texts(details_map.get("event_trigger")))
    event_texts.extend(_event_texts(details_map.get("event_triggers")))
    if event_texts:
        events = telemetry.setdefault("event_triggers", [])
        if not isinstance(events, list):
            events = []
            telemetry["event_triggers"] = events
        for text in event_texts:
            if text in events:
                continue
            events.append(text)
        if len(events) > EVENT_LOG_LIMIT:
            del events[:-EVENT_LOG_LIMIT]

    learning_feedback = payload.get("learning_feedback")
    if learning_feedback is None:
        learning_feedback = details_map.get("learning_feedback")
    if learning_feedback is not None:
        telemetry["learning_feedback"] = learning_feedback

    retry_count = (
        _coerce_int(payload.get("retry_count"))
        or _coerce_int(payload.get("retry_attempt"))
        or _coerce_int(details_map.get("retry_count"))
    )
    if retry_count is not None:
        telemetry["retry_count"] = max(
            int(telemetry.get("retry_count", 0) or 0),
            max(0, retry_count),
        )

    if stage_status == "error":
        previous_failure = int(telemetry.get("failure_count", 0) or 0)
        transitions = telemetry.get("stage_transitions", [])
        last_error_same_stage = (
            isinstance(transitions, list)
            and bool(transitions)
            and isinstance(transitions[-1], dict)
            and str(transitions[-1].get("stage")) == stage
            and str(transitions[-1].get("status")) == "error"
        )
        if not last_error_same_stage:
            telemetry["failure_count"] = previous_failure + 1
    if stage_status == "skipped":
        reason = str(payload.get("reason") or details_map.get("reason") or "").strip()
        skipped = telemetry.setdefault("skipped_stages", [])
        if isinstance(skipped, list):
            entry = {"stage": stage, "reason": reason}
            if entry not in skipped:
                skipped.append(entry)
            if len(skipped) > EVENT_LOG_LIMIT:
                del skipped[:-EVENT_LOG_LIMIT]

    telemetry["last_update_epoch"] = now


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
    """Track a stage as currently running for parallel execution support.

    When multiple stages run concurrently (e.g. nuclei + access_control),
    the job's top-level 'stage' field is set based on the stage with the
    highest baseline percentage, so the display always shows the "most
    advanced" stage rather than whichever wrote last.
    """
    active_stages = _get_active_stages(job)
    active_stages.add(stage)
    # Pick the stage with the highest baseline as the primary display
    best = max(active_stages, key=lambda s: STAGE_BASELINE_PERCENT.get(s, 0))
    job["stage"] = best
    job["stage_label"] = STAGE_LABELS.get(best, best.replace("_", " ").title())


def _mark_stage_done(job: dict[str, Any], stage: str) -> None:
    """Remove a stage from the active set when it completes."""
    active_stages = _get_active_stages(job)
    active_stages.discard(stage)
    if active_stages:
        best = max(active_stages, key=lambda s: STAGE_BASELINE_PERCENT.get(s, 0))
        job["stage"] = best
        job["stage_label"] = STAGE_LABELS.get(best, best.replace("_", " ").title())


LOG_RETENTION_LIMIT = 20


def append_log(job: dict[str, Any], line: str) -> None:
    clean = line.strip()
    if not clean:
        return
    if job["latest_logs"] and job["latest_logs"][-1] == clean:
        return
    job["latest_logs"].append(clean)
    job["latest_logs"] = job["latest_logs"][-LOG_RETENTION_LIMIT:]
    job["updated_at"] = time.time()


def _increment_state_version(job: dict[str, Any]) -> int:
    """Increment and return the new state_version for a job.

    state_version is the authoritative monotonic counter for job state
    changes. Every write to the job record increments this, and SSE events
    include it so clients can discard out-of-order or stale updates.
    """
    current = int(job.get("state_version", 0) or 0)
    new_version = current + 1
    job["state_version"] = new_version
    return new_version


def apply_progress(job: dict[str, Any], payload: dict[str, Any]) -> None:
    now = time.time()
    _increment_state_version(job)
    previous_stage = job.get("stage")
    stage = str(payload.get("stage", "")).strip() or job["stage"]

    processed = _coerce_int(payload.get("processed"))
    total = _coerce_int(payload.get("total"))

    # Track per-stage progress in a dict so all stages are visible simultaneously
    # FIX for parallel execution: don't unconditionally overwrite job["stage"]
    # and job["status_message"] when multiple stages emit progress concurrently
    stage_progress: dict[str, dict[str, Any]] = job.setdefault("stage_progress", {})
    is_new_stage = stage not in stage_progress

    if is_new_stage:
        stage_progress[stage] = {
            "stage": stage,
            "stage_label": STAGE_LABELS.get(stage, stage.replace("_", " ").title()),
            "status": "running",
            "processed": 0,
            "total": None,
            "percent": 0,
            "reason": "",
            "error": "",
            "retry_count": 0,
            "last_event": "",
            "started_at": now,
            "updated_at": now,
        }

    sp = stage_progress[stage]
    previous_status = _normalize_stage_status(sp.get("status"))
    stage_status = _normalize_stage_status(payload.get("status") or payload.get("stage_status"))

    # When progress moves to a new stage, close the previous stage if it was
    # still marked running and no explicit terminal event was emitted for it.
    if previous_stage and previous_stage != stage:
        previous_progress = stage_progress.get(previous_stage)
        if isinstance(previous_progress, dict) and previous_progress.get("status") == "running":
            _finalize_stage(job, previous_stage)
            if previous_progress.get("total") is None:
                previous_progress["percent"] = 100

    if processed is not None:
        sp["processed"] = max(0, processed)
    if total is not None and total > 0:
        sp["total"] = total
    sp["percent"] = _infer_stage_percent(stage, payload, int(sp.get("percent", 0) or 0))
    sp["updated_at"] = now
    sp["status"] = stage_status
    reason_text = str(payload.get("reason") or "").strip()
    error_text = str(payload.get("error") or "").strip()
    if reason_text:
        sp["reason"] = reason_text
    if error_text:
        sp["error"] = error_text
    retry_count = _coerce_int(payload.get("retry_count")) or _coerce_int(
        payload.get("retry_attempt")
    )
    if retry_count is not None:
        sp["retry_count"] = max(int(sp.get("retry_count", 0) or 0), max(0, retry_count))
    incoming_message = str(payload.get("message", "")).strip()
    if incoming_message:
        sp["last_event"] = incoming_message

    # Maintain parallel-safe stage tracking while supporting explicit terminal stage statuses.
    if stage_status == "running":
        _mark_stage_running(job, stage)
    else:
        _mark_stage_done(job, stage)

    # FIX: Only overwrite status_message when the stage actually changes,
    # preventing parallel stages from clobbering each other's messages.
    if (
        stage == "completed"
        and job.get("status") == "running"
        and incoming_message.lower() in {"run complete", "completed", "run completed"}
    ):
        incoming_message = "Finalizing run"

    if is_new_stage:
        job["status_message"] = incoming_message
    elif stage_status == "error" and incoming_message:
        job["status_message"] = incoming_message
    elif incoming_message and stage_status == "running" and stage == job.get("stage"):
        job["status_message"] = incoming_message
    elif not job.get("status_message"):
        job["status_message"] = incoming_message

    failed_stage = str(payload.get("failed_stage", "")).strip()
    failure_reason_code = str(payload.get("failure_reason_code", "")).strip()
    failure_step = str(payload.get("failure_step", "")).strip()
    explicit_failure_reason = str(
        payload.get("failure_reason") or payload.get("error") or ""
    ).strip()
    should_update_failure_fields = bool(
        failed_stage
        or failure_reason_code
        or failure_step
        or stage_status == "error"
        or explicit_failure_reason
    )
    failure_reason = explicit_failure_reason
    if stage_status == "error" and not failure_reason:
        failure_reason = str(payload.get("message") or "").strip()
    if stage_status == "error" and not failed_stage:
        failed_stage = stage
    if should_update_failure_fields:
        if failed_stage:
            job["failed_stage"] = failed_stage
        if failure_reason_code:
            job["failure_reason_code"] = failure_reason_code
        if failure_step:
            job["failure_step"] = failure_step
        if failure_reason:
            job["failure_reason"] = failure_reason
            if stage_status == "error":
                job["status_message"] = failure_reason
    payload_error = str(payload.get("error", "")).strip()
    if payload_error:
        job["error"] = payload_error

    if processed is not None and total is not None and total > 0:
        job["stage_processed"] = max(0, processed)
        job["stage_total"] = total
    elif previous_stage != stage:
        job["stage_processed"] = None
        job["stage_total"] = None

    _merge_progress_telemetry(
        job,
        payload=payload,
        stage=stage,
        stage_status=stage_status,
        now=now,
    )
    if stage_status != previous_status or is_new_stage:
        _record_stage_transition(
            job,
            stage=stage,
            status=stage_status,
            now=now,
            message=incoming_message,
        )

    inferred = _infer_percent(job, stage, payload)
    job["progress_percent"] = max(int(job.get("progress_percent", 0) or 0), inferred)
    job["updated_at"] = now
    _append_progress_history(job, now)

    if job["status_message"]:
        append_log(job, job["status_message"])


def _compute_eta_fallback(job: dict[str, Any], elapsed_seconds: float) -> float | None:
    return estimate_remaining(
        job["progress_percent"],
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
    """Mark a stage as completed in the stage_progress map."""
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
    """Apply terminal state (completed/failed/stopped) to the job record.

    Marks all still-running stages as completed and updates top-level fields.
    """
    now = time.time()
    _increment_state_version(job)
    job["status"] = status
    job["finished_at"] = now
    if error:
        job["error"] = error
    if returncode is not None:
        job["returncode"] = returncode

    # Mark all active stages as completed
    stage_progress: dict[str, dict[str, Any]] = job.setdefault("stage_progress", {})
    for sp in stage_progress.values():
        if sp.get("status") == "running":
            sp["status"] = "completed"
            sp["updated_at"] = now

    active_stages = _get_active_stages(job)
    active_stages.clear()


def _snapshot_progress_telemetry(
    job: dict[str, Any],
    *,
    now: float,
) -> dict[str, Any]:
    telemetry = _ensure_progress_telemetry(job)
    stage_progress = job.get("stage_progress")
    running_stages: list[tuple[str, dict[str, Any], float]] = []
    if isinstance(stage_progress, dict):
        for stage_name, payload in stage_progress.items():
            if not isinstance(payload, dict):
                continue
            status = _normalize_stage_status(payload.get("status"))
            if status != "running":
                continue
            started = _coerce_epoch(payload.get("started_at"), now)
            running_stages.append((stage_name, payload, started))

    if running_stages:
        bottleneck_stage, _, bottleneck_started = max(
            running_stages,
            key=lambda item: now - item[2],
        )
        telemetry.setdefault("bottleneck_stage", bottleneck_stage)
        telemetry.setdefault("bottleneck_seconds", round(max(0.0, now - bottleneck_started), 1))

    telemetry["active_task_count"] = max(
        int(telemetry.get("active_task_count", 0) or 0),
        _stage_running_count(job),
    )
    telemetry["last_update_epoch"] = _coerce_epoch(job.get("updated_at"), now)

    snapshot = dict(telemetry)
    snapshot["stage_transitions"] = list(telemetry.get("stage_transitions", []))[
        -TRANSITION_HISTORY_LIMIT:
    ]
    snapshot["event_triggers"] = list(telemetry.get("event_triggers", []))[-EVENT_LOG_LIMIT:]
    snapshot["skipped_stages"] = list(telemetry.get("skipped_stages", []))[-EVENT_LOG_LIMIT:]
    snapshot["top_active_targets"] = list(telemetry.get("top_active_targets", []))[:10]
    return snapshot


def snapshot_job(job: dict[str, Any]) -> dict[str, Any]:
    now = time.time()
    started_at = _coerce_epoch(job.get("started_at"), now)
    updated_at = _coerce_epoch(job.get("updated_at"), started_at)
    finished_at_raw = job.get("finished_at")
    finished_at = _coerce_epoch(finished_at_raw, 0.0) if finished_at_raw else None
    elapsed_seconds = (finished_at or now) - started_at

    status = str(job.get("status", "unknown"))
    stage = str(job.get("stage", "startup"))
    progress_percent = int(job.get("progress_percent", 0) or 0)

    if status == "running":
        from src.dashboard.fastapi.config import FeatureFlags

        if FeatureFlags.ENABLE_BAYESIAN_ETA():
            remaining_seconds = _compute_eta_bayesian(job, elapsed_seconds)
        else:
            remaining_seconds = _compute_eta_fallback(job, elapsed_seconds)
    else:
        remaining_seconds = 0

    since_update = now - updated_at
    stalled = status == "running" and since_update >= STALLED_AFTER_SECONDS
    stage_progress_label = _stage_progress_label(job)

    # Build ordered list of stage progress entries for the API response
    raw_stage_progress = job.get("stage_progress", {})

    # Handle legacy data where stage_progress was already serialized as a list
    if isinstance(raw_stage_progress, list):
        stage_progress_list = raw_stage_progress
    else:
        stage_order_list = [
            "startup",
            "subdomains",
            "live_hosts",
            "urls",
            "parameters",
            "ranking",
            "priority",
            "passive_scan",
            "active_scan",
            "nuclei",
            "access_control",
            "validation",
            "intelligence",
            "reporting",
            "completed",
        ]
        stage_progress_list = []
        for skey in stage_order_list:
            if skey in raw_stage_progress:
                sp = raw_stage_progress[skey]
                stage_progress_list.append(
                    {
                        "stage": sp.get("stage", skey),
                        "stage_label": sp.get(
                            "stage_label", STAGE_LABELS.get(skey, skey.replace("_", " ").title())
                        ),
                        "status": _normalize_stage_status(sp.get("status", "running")),
                        "processed": sp.get("processed", 0),
                        "total": sp.get("total"),
                        "percent": sp.get("percent", 0),
                        "reason": sp.get("reason", ""),
                        "error": sp.get("error", ""),
                        "retry_count": sp.get("retry_count", 0),
                        "last_event": sp.get("last_event", ""),
                        "started_at": sp.get("started_at"),
                        "updated_at": sp.get("updated_at"),
                    }
                )
        # Include any stages not in the predefined order
        for skey, sp in raw_stage_progress.items():
            if skey not in {s["stage"] for s in stage_progress_list}:
                stage_progress_list.append(
                    {
                        "stage": sp.get("stage", skey),
                        "stage_label": sp.get(
                            "stage_label", STAGE_LABELS.get(skey, skey.replace("_", " ").title())
                        ),
                        "status": _normalize_stage_status(sp.get("status", "running")),
                        "processed": sp.get("processed", 0),
                        "total": sp.get("total"),
                        "percent": sp.get("percent", 0),
                        "reason": sp.get("reason", ""),
                        "error": sp.get("error", ""),
                        "retry_count": sp.get("retry_count", 0),
                        "last_event": sp.get("last_event", ""),
                        "started_at": sp.get("started_at"),
                        "updated_at": sp.get("updated_at"),
                    }
                )

    return {
        "id": str(job.get("id", "")),
        "base_url": str(job.get("base_url", "")),
        "hostname": str(job.get("hostname", "")),
        "scope_entries": list(job.get("scope_entries", [])),
        "enabled_modules": list(job.get("enabled_modules", [])),
        "mode": job.get("mode", "idor"),
        "target_name": str(job.get("target_name", "")),
        "status": status,
        "started_at": datetime.fromtimestamp(started_at, tz=UTC).isoformat(),
        "updated_at": datetime.fromtimestamp(updated_at, tz=UTC).isoformat(),
        "finished_at": (
            datetime.fromtimestamp(finished_at, tz=UTC).isoformat()
            if finished_at is not None
            else None
        ),
        "started_at_label": format_epoch_ist(started_at),
        "updated_at_label": format_epoch_ist(updated_at),
        "finished_at_label": format_epoch_ist(finished_at),
        "stage": stage,
        "stage_label": str(
            job.get("stage_label", STAGE_LABELS.get(stage, stage.replace("_", " ").title()))
        ),
        "status_message": str(job.get("status_message", "")),
        "failed_stage": str(job.get("failed_stage", "")),
        "failure_reason_code": str(job.get("failure_reason_code", "")),
        "failure_step": str(job.get("failure_step", "")),
        "failure_reason": str(job.get("failure_reason", "")),
        "progress_percent": progress_percent,
        "returncode": job.get("returncode"),
        "error": str(job.get("error", "")),
        "warnings": list(job.get("warnings", [])),
        "warning_count": int(job.get("warning_count", len(job.get("warnings", [])) or 0) or 0),
        "stderr_warning_lines": list(job.get("stderr_warning_lines", [])),
        "stderr_fatal_lines": list(job.get("stderr_fatal_lines", [])),
        "fatal_signal_count": int(job.get("fatal_signal_count", 0) or 0),
        "timeout_events": list(job.get("timeout_events", [])),
        "degraded_providers": list(job.get("degraded_providers", [])),
        "configured_timeout_seconds": job.get("configured_timeout_seconds"),
        "effective_timeout_seconds": job.get("effective_timeout_seconds"),
        "execution_options": dict(job.get("execution_options", {})),
        "can_stop": status == "running",
        "latest_logs": list(job.get("latest_logs", [])),
        "config_href": str(job.get("config_href", "")),
        "scope_href": str(job.get("scope_href", "")),
        "stdout_href": str(job.get("stdout_href", "")),
        "stderr_href": str(job.get("stderr_href", "")),
        "target_href": str(job.get("target_href", "")),
        "elapsed_seconds": round(elapsed_seconds, 1),
        "elapsed_label": format_duration(elapsed_seconds),
        "eta_label": format_duration(remaining_seconds),
        "has_eta": remaining_seconds is not None,
        "last_update_label": format_duration(since_update),
        "stalled": stalled,
        "stage_progress_label": stage_progress_label,
        "stage_progress": stage_progress_list,
        "progress_telemetry": _snapshot_progress_telemetry(job, now=now),
        # Expose the count of concurrently running stages for the frontend
        "concurrent_stage_count": len(
            [
                s
                for s in (
                    raw_stage_progress.values() if isinstance(raw_stage_progress, dict) else []
                )
                if isinstance(s, dict) and s.get("status") == "running"
            ]
        ),
        "state_version": int(job.get("state_version", 0) or 0),
    }


"""Progress ingestion and stage updates management."""

import logging
import time
from typing import Any

from src.core.telemetry import build_telemetry_event, normalize_telemetry_event
from src.dashboard.job_state_helpers import (
    EVENT_LOG_LIMIT,
    PROGRESS_HISTORY_LIMIT,
    TRANSITION_HISTORY_LIMIT,
    _coerce_float,
    _coerce_int,
    _event_texts,
    _finalize_stage,
    _increment_state_version,
    _mark_stage_done,
    _mark_stage_running,
    _normalize_stage_status,
    append_log,
)
from src.dashboard.registry import STAGE_LABELS
from src.pipeline.constants.progress import STAGE_BASELINE_PERCENT

logger = logging.getLogger(__name__)
TELEMETRY_EVENT_LIMIT = 1000


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
        return max(0, min(100, stage_percent))

    processed = _coerce_int(payload.get("processed"))
    total = _coerce_int(payload.get("total"))
    if processed is not None and total and total > 0:
        derived = int((max(0, processed) / total) * 100)
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
    telemetry.setdefault("event_counts", {})
    telemetry.setdefault("artifact_counts", {})
    return telemetry


def _append_telemetry_event(job: dict[str, Any], event: dict[str, Any]) -> None:
    ledger = job.setdefault("telemetry_events", [])
    if not isinstance(ledger, list):
        ledger = []
        job["telemetry_events"] = ledger
    normalized = normalize_telemetry_event(event, fallback_stage=str(job.get("stage", "")))
    event_id = str(normalized.get("event_id", ""))
    if event_id and any(
        isinstance(item, dict) and item.get("event_id") == event_id for item in ledger[-50:]
    ):
        return
    ledger.append(normalized)
    if len(ledger) > TELEMETRY_EVENT_LIMIT:
        del ledger[:-TELEMETRY_EVENT_LIMIT]

    telemetry = _ensure_progress_telemetry(job)
    event_type = str(normalized.get("event_type") or "unknown")
    counts = telemetry.setdefault("event_counts", {})
    if isinstance(counts, dict):
        counts[event_type] = int(counts.get(event_type, 0) or 0) + 1
    artifact_type = str(normalized.get("artifact_type") or "")
    if artifact_type:
        artifact_counts = telemetry.setdefault("artifact_counts", {})
        if isinstance(artifact_counts, dict):
            artifact_counts[artifact_type] = int(artifact_counts.get(artifact_type, 0) or 0) + 1


def _ingest_payload_telemetry(
    job: dict[str, Any],
    *,
    payload: dict[str, Any],
    stage: str,
    stage_status: str,
    now: float,
) -> None:
    base = payload.get("telemetry_event")
    if isinstance(base, dict):
        _append_telemetry_event(job, base)
    else:
        _append_telemetry_event(
            job,
            build_telemetry_event(
                event_type="stage.progress",
                stage=stage,
                message=str(payload.get("message") or ""),
                status=stage_status,
                source=f"stage.{stage}",
                metrics={
                    "percent": _coerce_int(payload.get("percent")) or 0,
                    "stage_percent": _coerce_int(payload.get("stage_percent")) or 0,
                    "processed": _coerce_int(payload.get("processed")) or 0,
                    "total": _coerce_int(payload.get("total")) or 0,
                },
                epoch=now,
            ),
        )

    extra_events = payload.get("telemetry_events")
    if isinstance(extra_events, list):
        for event in extra_events:
            if isinstance(event, dict):
                _append_telemetry_event(job, event)

    telemetry_items = payload.get("telemetry_items")
    artifact_type = str(payload.get("artifact_type") or "")
    if isinstance(telemetry_items, list) and artifact_type:
        for index, item in enumerate(telemetry_items):
            artifact_id = str(item.get("id") if isinstance(item, dict) else item)
            if not artifact_id:
                continue
            _append_telemetry_event(
                job,
                build_telemetry_event(
                    event_type="artifact.discovered",
                    stage=stage,
                    message=f"{artifact_type} discovered: {artifact_id}",
                    status=stage_status,
                    source=f"stage.{stage}",
                    artifact_type=artifact_type,
                    artifact_id=artifact_id,
                    sequence=index + 1,
                    payload=item if isinstance(item, dict) else {"value": artifact_id},
                    epoch=now,
                ),
            )


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


def apply_progress(job: dict[str, Any], payload: dict[str, Any]) -> None:
    now = time.time()
    _increment_state_version(job)
    previous_stage = job.get("stage")
    stage = str(payload.get("stage", "")).strip() or job["stage"]

    processed = _coerce_int(payload.get("processed"))
    total = _coerce_int(payload.get("total"))

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

    if stage_status == "running":
        _mark_stage_running(job, stage)
    else:
        _mark_stage_done(job, stage)

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
    _ingest_payload_telemetry(
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

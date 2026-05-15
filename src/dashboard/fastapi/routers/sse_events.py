"""Typed SSE event emitter for the FastAPI dashboard.

Generates uniquely identified, sequence-numbered SSE events
in standard wire format. Thread-safe per-job sequence tracking.
"""

import json
import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

EVENT_TYPES = {
    "stage_change",
    "progress_update",
    "iteration_change",
    "finding_batch",
    "heartbeat",
    "completed",
    "error",
    "log",
    "note_event",
    "probe_event",
    "graph_event",
    "mesh_health_update",
}


class _SequenceTracker:
    """Thread-safe per-job sequence number tracker."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    def next(self, job_id: str) -> int:
        with self._lock:
            seq = self._counters.get(job_id, 0) + 1
            self._counters[job_id] = seq
            return seq

    def reset(self, job_id: str) -> None:
        with self._lock:
            self._counters[job_id] = 0


_global_tracker = _SequenceTracker()


class SSEEventEmitter:
    """Generates typed SSE events with unique IDs and sequence numbers."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id

    def _event_id(self) -> str:
        ts_ms = int(time.time() * 1000)
        seq = _global_tracker.next(self.job_id)
        return f"{self.job_id}-{ts_ms}-{seq:04d}"

    def emit(
        self,
        event_type: str,
        data: dict[str, Any],
        state_version: int | None = None,
    ) -> str:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"Unknown event type: {event_type}. Must be one of {EVENT_TYPES}")

        event_id = self._event_id()
        payload = {
            "event_type": event_type,
            "job_id": self.job_id,
            "timestamp": time.time(),
            "data": data,
        }
        if state_version is not None:
            payload["state_version"] = state_version
        return f"event: {event_type}\nid: {event_id}\ndata: {json.dumps(payload)}\n\n"

    def stage_change(
        self,
        previous_stage: str,
        new_stage: str,
        stage_label: str,
        progress_percent: int,
        stage_order: list[str] | None = None,
        stage_index: int = 0,
    ) -> str:
        return self.emit(
            "stage_change",
            {
                "previous_stage": previous_stage,
                "new_stage": new_stage,
                "stage_label": stage_label,
                "progress_percent": progress_percent,
                "stage_order": stage_order or [],
                "stage_index": stage_index,
            },
        )

    def progress_update(
        self,
        stage: str,
        stage_label: str,
        progress_percent: int,
        message: str = "",
        stage_processed: int | None = None,
        stage_total: int | None = None,
        stage_percent: int | None = None,
        plugin_group: str | None = None,
        plugin_label: str | None = None,
        processed: int | None = None,
        total: int | None = None,
        percent: int | None = None,
        current_plugin: str | None = None,
        status: str | None = None,
        error_message: str | None = None,
        failed_stage: str | None = None,
        failure_reason_code: str | None = None,
        failure_step: str | None = None,
        failure_reason: str | None = None,
        stage_status: str | None = None,
        stage_reason: str | None = None,
        stage_error: str | None = None,
        retry_count: int | None = None,
        stage_progress: list[dict[str, Any]] | None = None,
        progress_telemetry: dict[str, Any] | None = None,
        state_version: int | None = None,
    ) -> str:
        data: dict[str, Any] = {
            "stage": stage,
            "stage_label": stage_label,
            "progress_percent": progress_percent,
            "message": message,
        }
        if stage_processed is not None:
            data["stage_processed"] = stage_processed
        if stage_total is not None:
            data["stage_total"] = stage_total
        if stage_percent is not None:
            data["stage_percent"] = stage_percent
        if plugin_group is not None:
            data["plugin_group"] = plugin_group
        if plugin_label is not None:
            data["plugin_label"] = plugin_label
        if processed is not None:
            data["processed"] = processed
        if total is not None:
            data["total"] = total
        if percent is not None:
            data["percent"] = percent
        if current_plugin is not None:
            data["current_plugin"] = current_plugin
        if status is not None:
            data["status"] = status
        if error_message is not None:
            data["error_message"] = error_message
        if failed_stage is not None:
            data["failed_stage"] = failed_stage
        if failure_reason_code is not None:
            data["failure_reason_code"] = failure_reason_code
        if failure_step is not None:
            data["failure_step"] = failure_step
        if failure_reason is not None:
            data["failure_reason"] = failure_reason
        if stage_status is not None:
            data["stage_status"] = stage_status
        if stage_reason is not None:
            data["stage_reason"] = stage_reason
        if stage_error is not None:
            data["stage_error"] = stage_error
        if retry_count is not None:
            data["retry_count"] = retry_count
        if stage_progress is not None:
            data["stage_progress"] = stage_progress
        if progress_telemetry is not None:
            data["progress_telemetry"] = progress_telemetry
        return self.emit("progress_update", data, state_version=state_version)

    def iteration_change(
        self,
        current_iteration: int,
        max_iterations: int,
        stage: str,
        stage_percent: int,
        progress_percent: int,
        previous_iteration_findings: int = 0,
        previous_iteration_new_keys: int = 0,
    ) -> str:
        return self.emit(
            "iteration_change",
            {
                "current_iteration": current_iteration,
                "max_iterations": max_iterations,
                "stage": stage,
                "stage_percent": stage_percent,
                "progress_percent": progress_percent,
                "previous_iteration_findings": previous_iteration_findings,
                "previous_iteration_new_keys": previous_iteration_new_keys,
            },
        )

    def finding_batch(
        self,
        findings: list[dict[str, Any]],
        batch_id: str,
        total_findings_so_far: int,
        iteration: int = 0,
    ) -> str:
        return self.emit(
            "finding_batch",
            {
                "batch_id": batch_id,
                "findings": findings,
                "batch_size": len(findings),
                "total_findings_so_far": total_findings_so_far,
                "iteration": iteration,
            },
        )

    def heartbeat(
        self,
        progress_percent: int,
        stage: str,
        stage_label: str,
        stalled: bool,
        seconds_since_last_update: float,
    ) -> str:
        return self.emit(
            "heartbeat",
            {
                "progress_percent": progress_percent,
                "stage": stage,
                "stage_label": stage_label,
                "stalled": stalled,
                "seconds_since_last_update": round(seconds_since_last_update, 1),
            },
        )

    def completed(
        self,
        status: str,
        progress_percent: int,
        stage: str,
        stage_label: str,
        total_duration_seconds: float,
        total_findings: int,
        iterations_completed: int = 0,
        failed_stage: str | None = None,
        failure_reason_code: str | None = None,
        failure_step: str | None = None,
        failure_reason: str | None = None,
        stage_progress: list[dict[str, Any]] | None = None,
        progress_telemetry: dict[str, Any] | None = None,
    ) -> str:
        data: dict[str, Any] = {
            "status": status,
            "progress_percent": progress_percent,
            "stage": stage,
            "stage_label": stage_label,
            "total_duration_seconds": total_duration_seconds,
            "total_findings": total_findings,
            "iterations_completed": iterations_completed,
        }
        if failed_stage is not None:
            data["failed_stage"] = failed_stage
        if failure_reason_code is not None:
            data["failure_reason_code"] = failure_reason_code
        if failure_step is not None:
            data["failure_step"] = failure_step
        if failure_reason is not None:
            data["failure_reason"] = failure_reason
        if stage_progress is not None:
            data["stage_progress"] = stage_progress
        if progress_telemetry is not None:
            data["progress_telemetry"] = progress_telemetry
        return self.emit("completed", data)

    def error(
        self,
        error: str,
        stage: str,
        progress_percent: int,
        recoverable: bool = True,
        failed_stage: str | None = None,
        failure_reason_code: str | None = None,
        failure_step: str | None = None,
        failure_reason: str | None = None,
        details: dict[str, Any] | None = None,
        fatal: bool | None = None,
        stage_progress: list[dict[str, Any]] | None = None,
        progress_telemetry: dict[str, Any] | None = None,
    ) -> str:
        data: dict[str, Any] = {
            "error": error,
            "stage": stage,
            "progress_percent": progress_percent,
            "recoverable": recoverable,
        }
        if failed_stage is not None:
            data["failed_stage"] = failed_stage
        if failure_reason_code is not None:
            data["failure_reason_code"] = failure_reason_code
        if failure_step is not None:
            data["failure_step"] = failure_step
        if failure_reason is not None:
            data["failure_reason"] = failure_reason
        if details is not None:
            data["details"] = details
        if fatal is not None:
            data["fatal"] = fatal
        if stage_progress is not None:
            data["stage_progress"] = stage_progress
        if progress_telemetry is not None:
            data["progress_telemetry"] = progress_telemetry
        return self.emit("error", data)

    def log(self, line: str) -> str:
        return self.emit("log", {"line": line})

    def note_event(self, action: str, note_data: dict[str, Any]) -> str:
        """Emit an event when a note is created, updated, or deleted."""
        return self.emit(
            "note_event",
            {
                "action": action,
                "note": note_data,
            },
        )

    def probe_event(self, action: str, probe_data: dict[str, Any]) -> str:
        """Emit an event when a probe is triggered or updated."""
        return self.emit(
            "probe_event",
            {
                "action": action,
                "probe": probe_data,
            },
        )

    def graph_event(self, action: str, graph_data: dict[str, Any]) -> str:
        """Emit an event when the threat graph changes."""
        return self.emit(
            "graph_event",
            {
                "action": action,
                "graph": graph_data,
            },
        )

    def mesh_health_update(self, mesh_health: dict[str, Any]) -> str:
        """Emit current mesh health while a job is active."""
        return self.emit("mesh_health_update", mesh_health)

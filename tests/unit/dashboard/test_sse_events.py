"""Tests for SSEEventEmitter from src.dashboard.fastapi.routers.sse_events."""

import json
import re
from collections.abc import Generator

import pytest

from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_global_tracker() -> Generator[None]:
    """Reset the global sequence tracker before each test."""
    _global_tracker._counters.clear()
    yield


@pytest.fixture
def emitter() -> SSEEventEmitter:
    """Return an SSEEventEmitter for a test job."""
    return SSEEventEmitter(job_id="test-job-001")


# ===========================================================================
# 1. test_emit_stage_change
# ===========================================================================


class TestEmitStageChange:
    def test_emit_stage_change(self, emitter: SSEEventEmitter) -> None:
        """Verify correct SSE wire format, event ID pattern, all fields present."""
        result = emitter.stage_change(
            previous_stage="startup",
            new_stage="subdomains",
            stage_label="Subdomain Discovery",
            progress_percent=10,
            stage_order=["startup", "subdomains", "live_hosts"],
            stage_index=1,
        )

        assert result.startswith("event: stage_change\n")
        assert "id: test-job-001-" in result
        assert result.endswith("\n\n")

        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "stage_change"
        assert payload["job_id"] == "test-job-001"
        assert "timestamp" in payload
        assert payload["data"]["previous_stage"] == "startup"
        assert payload["data"]["new_stage"] == "subdomains"
        assert payload["data"]["stage_label"] == "Subdomain Discovery"
        assert payload["data"]["progress_percent"] == 10
        assert payload["data"]["stage_order"] == ["startup", "subdomains", "live_hosts"]
        assert payload["data"]["stage_index"] == 1

    def test_stage_change_defaults(self, emitter: SSEEventEmitter) -> None:
        """stage_change uses defaults for optional fields."""
        result = emitter.stage_change(
            previous_stage="a",
            new_stage="b",
            stage_label="B Stage",
            progress_percent=50,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])
        assert payload["data"]["stage_order"] == []
        assert payload["data"]["stage_index"] == 0


# ===========================================================================
# 2. test_emit_progress_update
# ===========================================================================


class TestEmitProgressUpdate:
    def test_emit_progress_update_required_fields(self, emitter: SSEEventEmitter) -> None:
        """Verify progress_update event with required fields."""
        result = emitter.progress_update(
            stage="subdomains",
            stage_label="Subdomain Discovery",
            progress_percent=25,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "progress_update"
        assert payload["data"]["stage"] == "subdomains"
        assert payload["data"]["stage_label"] == "Subdomain Discovery"
        assert payload["data"]["progress_percent"] == 25
        assert payload["data"]["message"] == ""

    def test_emit_progress_update_all_optional_fields(self, emitter: SSEEventEmitter) -> None:
        """Verify progress_update with all optional fields included."""
        result = emitter.progress_update(
            stage="nuclei",
            stage_label="Nuclei Scan",
            progress_percent=60,
            message="Processing template 50/100",
            stage_processed=50,
            stage_total=100,
            stage_percent=50,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["message"] == "Processing template 50/100"
        assert payload["data"]["stage_processed"] == 50
        assert payload["data"]["stage_total"] == 100
        assert payload["data"]["stage_percent"] == 50

    def test_emit_progress_update_omits_none_optionals(self, emitter: SSEEventEmitter) -> None:
        """Optional fields set to None are omitted from data."""
        result = emitter.progress_update(
            stage="urls",
            stage_label="URL Discovery",
            progress_percent=30,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert "stage_processed" not in payload["data"]
        assert "stage_total" not in payload["data"]
        assert "stage_percent" not in payload["data"]


# ===========================================================================
# 3. test_emit_iteration_change
# ===========================================================================


class TestEmitIterationChange:
    def test_emit_iteration_change(self, emitter: SSEEventEmitter) -> None:
        """Verify iteration_change event."""
        result = emitter.iteration_change(
            current_iteration=2,
            max_iterations=5,
            stage="analysis",
            stage_percent=40,
            progress_percent=35,
            previous_iteration_findings=3,
            previous_iteration_new_keys=1,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "iteration_change"
        assert payload["data"]["current_iteration"] == 2
        assert payload["data"]["max_iterations"] == 5
        assert payload["data"]["stage"] == "analysis"
        assert payload["data"]["stage_percent"] == 40
        assert payload["data"]["progress_percent"] == 35
        assert payload["data"]["previous_iteration_findings"] == 3
        assert payload["data"]["previous_iteration_new_keys"] == 1

    def test_iteration_change_defaults(self, emitter: SSEEventEmitter) -> None:
        """iteration_change uses zero defaults."""
        result = emitter.iteration_change(
            current_iteration=1,
            max_iterations=3,
            stage="urls",
            stage_percent=10,
            progress_percent=10,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["previous_iteration_findings"] == 0
        assert payload["data"]["previous_iteration_new_keys"] == 0


# ===========================================================================
# 4. test_emit_finding_batch
# ===========================================================================


class TestEmitFindingBatch:
    def test_emit_finding_batch(self, emitter: SSEEventEmitter) -> None:
        """Verify finding_batch with multiple findings."""
        findings = [
            {"template_id": "t1", "severity": "high", "url": "https://a.com"},
            {"template_id": "t2", "severity": "medium", "url": "https://b.com"},
            {"template_id": "t3", "severity": "low", "url": "https://c.com"},
        ]
        result = emitter.finding_batch(
            findings=findings,
            batch_id="batch-001",
            total_findings_so_far=15,
            iteration=2,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "finding_batch"
        assert payload["data"]["batch_id"] == "batch-001"
        assert len(payload["data"]["findings"]) == 3
        assert payload["data"]["batch_size"] == 3
        assert payload["data"]["total_findings_so_far"] == 15
        assert payload["data"]["iteration"] == 2

    def test_finding_batch_empty_findings(self, emitter: SSEEventEmitter) -> None:
        """finding_batch handles empty findings list."""
        result = emitter.finding_batch(
            findings=[],
            batch_id="batch-empty",
            total_findings_so_far=0,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["batch_size"] == 0
        assert payload["data"]["findings"] == []


# ===========================================================================
# 5. test_emit_heartbeat
# ===========================================================================


class TestEmitHeartbeat:
    def test_emit_heartbeat(self, emitter: SSEEventEmitter) -> None:
        """Verify heartbeat event."""
        result = emitter.heartbeat(
            progress_percent=50,
            stage="nuclei",
            stage_label="Nuclei Scan",
            stalled=False,
            seconds_since_last_update=30.5,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "heartbeat"
        assert payload["data"]["progress_percent"] == 50
        assert payload["data"]["stage"] == "nuclei"
        assert payload["data"]["stage_label"] == "Nuclei Scan"
        assert payload["data"]["stalled"] is False
        assert payload["data"]["seconds_since_last_update"] == 30.5

    def test_heartbeat_stalled_true(self, emitter: SSEEventEmitter) -> None:
        """heartbeat with stalled=True."""
        result = emitter.heartbeat(
            progress_percent=50,
            stage="nuclei",
            stage_label="Nuclei Scan",
            stalled=True,
            seconds_since_last_update=120.7,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["stalled"] is True
        assert payload["data"]["seconds_since_last_update"] == 120.7


# ===========================================================================
# 6. test_emit_completed
# ===========================================================================


class TestEmitCompleted:
    def test_emit_completed(self, emitter: SSEEventEmitter) -> None:
        """Verify completed event."""
        result = emitter.completed(
            status="success",
            progress_percent=100,
            stage="completed",
            stage_label="Completed",
            total_duration_seconds=345.6,
            total_findings=42,
            iterations_completed=5,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "completed"
        assert payload["data"]["status"] == "success"
        assert payload["data"]["progress_percent"] == 100
        assert payload["data"]["stage"] == "completed"
        assert payload["data"]["stage_label"] == "Completed"
        assert payload["data"]["total_duration_seconds"] == 345.6
        assert payload["data"]["total_findings"] == 42
        assert payload["data"]["iterations_completed"] == 5

    def test_completed_defaults(self, emitter: SSEEventEmitter) -> None:
        """completed uses zero default for iterations_completed."""
        result = emitter.completed(
            status="failed",
            progress_percent=60,
            stage="nuclei",
            stage_label="Nuclei Scan",
            total_duration_seconds=100.0,
            total_findings=10,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["iterations_completed"] == 0


# ===========================================================================
# 7. test_emit_error
# ===========================================================================


class TestEmitError:
    def test_emit_error(self, emitter: SSEEventEmitter) -> None:
        """Verify error event."""
        result = emitter.error(
            error="Connection timeout",
            stage="subdomains",
            progress_percent=20,
            recoverable=True,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "error"
        assert payload["data"]["error"] == "Connection timeout"
        assert payload["data"]["stage"] == "subdomains"
        assert payload["data"]["progress_percent"] == 20
        assert payload["data"]["recoverable"] is True

    def test_error_non_recoverable(self, emitter: SSEEventEmitter) -> None:
        """error with recoverable=False."""
        result = emitter.error(
            error="Fatal crash",
            stage="reporting",
            progress_percent=90,
            recoverable=False,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["recoverable"] is False

    def test_error_default_recoverable(self, emitter: SSEEventEmitter) -> None:
        """error defaults recoverable to True."""
        result = emitter.error(
            error="Some error",
            stage="urls",
            progress_percent=50,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["recoverable"] is True


# ===========================================================================
# 8. test_emit_log
# ===========================================================================


class TestEmitLog:
    def test_emit_log(self, emitter: SSEEventEmitter) -> None:
        """Verify log event."""
        result = emitter.log(line="[INFO] Starting subdomain enumeration")
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "log"
        assert payload["data"]["line"] == "[INFO] Starting subdomain enumeration"

    def test_log_empty_line(self, emitter: SSEEventEmitter) -> None:
        """log handles empty line."""
        result = emitter.log(line="")
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["line"] == ""


# ===========================================================================
# 9. test_emit_unknown_event_type_raises
# ===========================================================================


class TestEmitUnknownEventType:
    def test_emit_unknown_event_type_raises(self, emitter: SSEEventEmitter) -> None:
        """ValueError for unknown types."""
        with pytest.raises(ValueError, match="Unknown event type"):
            emitter.emit("unknown_type", {"key": "value"})

    def test_emit_unknown_event_type_message_includes_valid_types(
        self, emitter: SSEEventEmitter
    ) -> None:
        """Error message includes the set of valid event types."""
        with pytest.raises(ValueError) as exc_info:
            emitter.emit("bogus", {})
        assert "bogus" in str(exc_info.value)


# ===========================================================================
# 10. test_event_id_format
# ===========================================================================


class TestEventIdFormat:
    def test_event_id_format(self, emitter: SSEEventEmitter) -> None:
        """Verify <job_id>-<timestamp_ms>-<seq> pattern."""
        result = emitter.emit("log", {"line": "test"})
        id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
        event_id = id_line[len("id: ") :]

        pattern = r"^test-job-001-\d{13}-\d{4}$"
        assert re.match(pattern, event_id), f"Event ID '{event_id}' does not match pattern"

    def test_event_id_contains_job_id(self, emitter: SSEEventEmitter) -> None:
        """Event ID starts with the job_id."""
        result = emitter.emit("log", {"line": "test"})
        id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
        event_id = id_line[len("id: ") :]

        assert event_id.startswith("test-job-001-")

    def test_event_id_sequence_is_zero_padded(self, emitter: SSEEventEmitter) -> None:
        """Sequence number is zero-padded to 4 digits."""
        result = emitter.emit("log", {"line": "test"})
        id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
        event_id = id_line[len("id: ") :]

        seq_part = event_id.split("-")[-1]
        assert len(seq_part) == 4
        assert seq_part == "0001"


# ===========================================================================
# 11. test_sequence_increments_per_job
# ===========================================================================


class TestSequenceIncrements:
    def test_sequence_increments_per_job(self, emitter: SSEEventEmitter) -> None:
        """Multiple emits increment sequence."""
        results = [emitter.emit("log", {"line": f"msg {i}"}) for i in range(5)]

        sequences = []
        for result in results:
            id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
            event_id = id_line[len("id: ") :]
            seq = int(event_id.split("-")[-1])
            sequences.append(seq)

        assert sequences == [1, 2, 3, 4, 5]


# ===========================================================================
# 12. test_sequence_per_job_isolation
# ===========================================================================


class TestSequencePerJobIsolation:
    def test_sequence_per_job_isolation(self) -> None:
        """Different jobs have independent sequences."""
        emitter_a = SSEEventEmitter(job_id="job-a")
        emitter_b = SSEEventEmitter(job_id="job-b")

        result_a1 = emitter_a.emit("log", {"line": "a1"})
        result_b1 = emitter_b.emit("log", {"line": "b1"})
        result_a2 = emitter_a.emit("log", {"line": "a2"})
        result_b2 = emitter_b.emit("log", {"line": "b2"})

        def get_seq(result: str) -> int:
            id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
            event_id = id_line[len("id: ") :]
            return int(event_id.split("-")[-1])

        assert get_seq(result_a1) == 1
        assert get_seq(result_b1) == 1
        assert get_seq(result_a2) == 2
        assert get_seq(result_b2) == 2


# ===========================================================================
# 13. test_data_is_valid_json
# ===========================================================================


class TestDataIsValidJson:
    def test_data_is_valid_json(self, emitter: SSEEventEmitter) -> None:
        """All emitted events have parseable JSON data."""
        events = [
            emitter.stage_change("a", "b", "B", 10),
            emitter.progress_update("subdomains", "Subdomains", 20),
            emitter.iteration_change(1, 5, "analysis", 40, 35),
            emitter.finding_batch([{"id": 1}], "batch-1", 1),
            emitter.heartbeat(50, "nuclei", "Nuclei", False, 30.0),
            emitter.completed("success", 100, "completed", "Completed", 300.0, 10),
            emitter.error("err", "urls", 50),
            emitter.log("test log line"),
        ]

        for event in events:
            data_line = [line for line in event.split("\n") if line.startswith("data: ")][0]
            payload = json.loads(data_line[len("data: ") :])
            assert "event_type" in payload
            assert "job_id" in payload
            assert "timestamp" in payload
            assert "data" in payload

    def test_timestamp_is_numeric(self, emitter: SSEEventEmitter) -> None:
        """Timestamp field is a numeric value."""
        result = emitter.emit("log", {"line": "test"})
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert isinstance(payload["timestamp"], (int, float))
        assert payload["timestamp"] > 0


# ===========================================================================
# 14. test_sse_wire_format
# ===========================================================================


class TestSSEWireFormat:
    def test_sse_wire_format(self, emitter: SSEEventEmitter) -> None:
        """Verify event:, id:, data: prefix lines."""
        result = emitter.emit(
            "stage_change",
            {
                "previous_stage": "a",
                "new_stage": "b",
                "stage_label": "B",
                "progress_percent": 10,
                "stage_order": [],
                "stage_index": 0,
            },
        )

        lines = result.split("\n")
        assert lines[0].startswith("event: ")
        assert lines[1].startswith("id: ")
        assert lines[2].startswith("data: ")
        assert lines[3] == ""

    def test_sse_format_event_prefix(self, emitter: SSEEventEmitter) -> None:
        """event: line contains the event type."""
        result = emitter.emit(
            "heartbeat",
            {
                "progress_percent": 0,
                "stage": "startup",
                "stage_label": "Startup",
                "stalled": False,
                "seconds_since_last_update": 0.0,
            },
        )
        assert "event: heartbeat\n" in result

    def test_sse_format_data_is_single_line(self, emitter: SSEEventEmitter) -> None:
        """data: line does not contain newlines within the JSON."""
        result = emitter.finding_batch(
            findings=[{"id": i, "name": f"finding-{i}"} for i in range(10)],
            batch_id="big-batch",
            total_findings_so_far=100,
        )
        data_lines = [line for line in result.split("\n") if line.startswith("data: ")]
        assert len(data_lines) == 1

    def test_sse_format_terminates_with_double_newline(self, emitter: SSEEventEmitter) -> None:
        """SSE event message ends with \\n\\n."""
        result = emitter.emit("log", {"line": "test"})
        assert result.endswith("\n\n")


# ===========================================================================
# Additional: SequenceTracker unit tests
# ===========================================================================


class TestSequenceTracker:
    def test_next_starts_at_one(self) -> None:
        """First call to next returns 1."""
        tracker = _SequenceTracker()
        assert tracker.next("job-1") == 1

    def test_next_increments(self) -> None:
        """Subsequent calls increment."""
        tracker = _SequenceTracker()
        assert tracker.next("job-1") == 1
        assert tracker.next("job-1") == 2
        assert tracker.next("job-1") == 3

    def test_next_independent_per_job(self) -> None:
        """Different jobs have independent counters."""
        tracker = _SequenceTracker()
        assert tracker.next("job-a") == 1
        assert tracker.next("job-b") == 1
        assert tracker.next("job-a") == 2
        assert tracker.next("job-b") == 2

    def test_reset_sets_counter_to_zero(self) -> None:
        """reset sets counter to 0 so next returns 1."""
        tracker = _SequenceTracker()
        tracker.next("job-1")
        tracker.next("job-1")
        tracker.reset("job-1")
        assert tracker.next("job-1") == 1

import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
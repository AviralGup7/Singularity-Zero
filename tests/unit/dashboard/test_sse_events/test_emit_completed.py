import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
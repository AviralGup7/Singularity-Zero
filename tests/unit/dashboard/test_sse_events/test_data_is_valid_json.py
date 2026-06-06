import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
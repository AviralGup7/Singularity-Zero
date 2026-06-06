import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



class TestEventIdFormat:
    def test_event_id_format(self, emitter: SSEEventEmitter) -> None:
        """Verify <job_id>:<timestamp_ms>:<seq>:<last_count>:<stage>:<iteration> pattern."""
        result = emitter.emit("log", {"line": "test"})
        id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
        event_id = id_line[len("id: ") :]

        pattern = r"^test-job-001:\d{13}:\d{4}:\d+:[^:]*:\d+$"
        assert re.match(pattern, event_id), f"Event ID '{event_id}' does not match pattern"

    def test_event_id_contains_job_id(self, emitter: SSEEventEmitter) -> None:
        """Event ID starts with the job_id followed by a colon."""
        result = emitter.emit("log", {"line": "test"})
        id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
        event_id = id_line[len("id: ") :]

        assert event_id.startswith("test-job-001:")

    def test_event_id_sequence_is_zero_padded(self, emitter: SSEEventEmitter) -> None:
        """Sequence number is zero-padded to 4 digits."""
        result = emitter.emit("log", {"line": "test"})
        id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
        event_id = id_line[len("id: ") :]

        seq_part = event_id.split(":")[2]
        assert len(seq_part) == 4
        assert seq_part == "0001"
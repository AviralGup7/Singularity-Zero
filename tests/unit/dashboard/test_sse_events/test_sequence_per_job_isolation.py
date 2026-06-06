import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
            return int(event_id.split(":")[2])

        assert get_seq(result_a1) == 1
        assert get_seq(result_b1) == 1
        assert get_seq(result_a2) == 2
        assert get_seq(result_b2) == 2
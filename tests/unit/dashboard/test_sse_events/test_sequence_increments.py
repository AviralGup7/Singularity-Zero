import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



class TestSequenceIncrements:
    def test_sequence_increments_per_job(self, emitter: SSEEventEmitter) -> None:
        """Multiple emits increment sequence."""
        results = [emitter.emit("log", {"line": f"msg {i}"}) for i in range(5)]

        sequences = []
        for result in results:
            id_line = [line for line in result.split("\n") if line.startswith("id: ")][0]
            event_id = id_line[len("id: ") :]
            seq = int(event_id.split(":")[2])
            sequences.append(seq)

        assert sequences == [1, 2, 3, 4, 5]
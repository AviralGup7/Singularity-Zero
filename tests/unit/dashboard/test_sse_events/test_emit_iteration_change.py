import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
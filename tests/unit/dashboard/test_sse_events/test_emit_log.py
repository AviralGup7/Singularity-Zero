import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
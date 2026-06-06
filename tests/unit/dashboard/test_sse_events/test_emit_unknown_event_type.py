import json
import re
from collections.abc import Generator
import pytest
from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
    _global_tracker,
    _SequenceTracker,
)



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
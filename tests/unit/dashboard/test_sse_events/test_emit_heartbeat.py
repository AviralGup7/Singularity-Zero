import json

from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
)


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

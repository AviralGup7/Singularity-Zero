import json

from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
)


class TestEmitError:
    def test_emit_error(self, emitter: SSEEventEmitter) -> None:
        """Verify error event."""
        result = emitter.error(
            error="Connection timeout",
            stage="subdomains",
            progress_percent=20,
            recoverable=True,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "error"
        assert payload["data"]["error"] == "Connection timeout"
        assert payload["data"]["stage"] == "subdomains"
        assert payload["data"]["progress_percent"] == 20
        assert payload["data"]["recoverable"] is True

    def test_error_non_recoverable(self, emitter: SSEEventEmitter) -> None:
        """error with recoverable=False."""
        result = emitter.error(
            error="Fatal crash",
            stage="reporting",
            progress_percent=90,
            recoverable=False,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["recoverable"] is False

    def test_error_default_recoverable(self, emitter: SSEEventEmitter) -> None:
        """error defaults recoverable to True."""
        result = emitter.error(
            error="Some error",
            stage="urls",
            progress_percent=50,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["recoverable"] is True

import json

from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
)


class TestEmitProgressUpdate:
    def test_emit_progress_update_required_fields(self, emitter: SSEEventEmitter) -> None:
        """Verify progress_update event with required fields."""
        result = emitter.progress_update(
            stage="subdomains",
            stage_label="Subdomain Discovery",
            progress_percent=25,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "progress_update"
        assert payload["data"]["stage"] == "subdomains"
        assert payload["data"]["stage_label"] == "Subdomain Discovery"
        assert payload["data"]["progress_percent"] == 25
        assert payload["data"]["message"] == ""

    def test_emit_progress_update_all_optional_fields(self, emitter: SSEEventEmitter) -> None:
        """Verify progress_update with all optional fields included."""
        result = emitter.progress_update(
            stage="nuclei",
            stage_label="Nuclei Scan",
            progress_percent=60,
            message="Processing template 50/100",
            stage_processed=50,
            stage_total=100,
            stage_percent=50,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["message"] == "Processing template 50/100"
        assert payload["data"]["stage_processed"] == 50
        assert payload["data"]["stage_total"] == 100
        assert payload["data"]["stage_percent"] == 50

    def test_emit_progress_update_omits_none_optionals(self, emitter: SSEEventEmitter) -> None:
        """Optional fields set to None are omitted from data."""
        result = emitter.progress_update(
            stage="urls",
            stage_label="URL Discovery",
            progress_percent=30,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert "stage_processed" not in payload["data"]
        assert "stage_total" not in payload["data"]
        assert "stage_percent" not in payload["data"]

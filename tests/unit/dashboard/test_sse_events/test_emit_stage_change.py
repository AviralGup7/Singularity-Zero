import json

from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
)


class TestEmitStageChange:
    def test_emit_stage_change(self, emitter: SSEEventEmitter) -> None:
        """Verify correct SSE wire format, event ID pattern, all fields present."""
        result = emitter.stage_change(
            previous_stage="startup",
            new_stage="subdomains",
            stage_label="Subdomain Discovery",
            progress_percent=10,
            stage_order=["startup", "subdomains", "live_hosts"],
            stage_index=1,
        )

        assert result.startswith("event: stage_change\n")
        assert "id: test-job-001:" in result
        assert result.endswith("\n\n")

        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "stage_change"
        assert payload["job_id"] == "test-job-001"
        assert "timestamp" in payload
        assert payload["data"]["previous_stage"] == "startup"
        assert payload["data"]["new_stage"] == "subdomains"
        assert payload["data"]["stage_label"] == "Subdomain Discovery"
        assert payload["data"]["progress_percent"] == 10
        assert payload["data"]["stage_order"] == ["startup", "subdomains", "live_hosts"]
        assert payload["data"]["stage_index"] == 1

    def test_stage_change_defaults(self, emitter: SSEEventEmitter) -> None:
        """stage_change uses defaults for optional fields."""
        result = emitter.stage_change(
            previous_stage="a",
            new_stage="b",
            stage_label="B Stage",
            progress_percent=50,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])
        assert payload["data"]["stage_order"] == []
        assert payload["data"]["stage_index"] == 0

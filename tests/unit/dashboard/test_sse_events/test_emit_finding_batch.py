import json

from src.dashboard.fastapi.routers.sse_events import (
    SSEEventEmitter,
)


class TestEmitFindingBatch:
    def test_emit_finding_batch(self, emitter: SSEEventEmitter) -> None:
        """Verify finding_batch with multiple findings."""
        findings = [
            {"template_id": "t1", "severity": "high", "url": "https://a.com"},
            {"template_id": "t2", "severity": "medium", "url": "https://b.com"},
            {"template_id": "t3", "severity": "low", "url": "https://c.com"},
        ]
        result = emitter.finding_batch(
            findings=findings,
            batch_id="batch-001",
            total_findings_so_far=15,
            iteration=2,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["event_type"] == "finding_batch"
        assert payload["data"]["batch_id"] == "batch-001"
        assert len(payload["data"]["findings"]) == 3
        assert payload["data"]["batch_size"] == 3
        assert payload["data"]["total_findings_so_far"] == 15
        assert payload["data"]["iteration"] == 2

    def test_finding_batch_empty_findings(self, emitter: SSEEventEmitter) -> None:
        """finding_batch handles empty findings list."""
        result = emitter.finding_batch(
            findings=[],
            batch_id="batch-empty",
            total_findings_so_far=0,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: ") :])

        assert payload["data"]["batch_size"] == 0
        assert payload["data"]["findings"] == []

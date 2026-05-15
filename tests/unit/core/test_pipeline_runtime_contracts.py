from types import MappingProxyType

import pytest

from src.core.contracts.pipeline_runtime import (
    PipelineInput,
    StageInput,
    StageOutcome,
    StageOutput,
)


@pytest.mark.unit
def test_stage_input_uses_immutable_snapshot() -> None:
    pipeline_input = PipelineInput(
        target_name="example.com",
        scope_entries=("example.com",),
        run_id="run-123",
        metadata={"mode": "test"},
    )
    external_snapshot = {
        "counts": {"urls": 1},
        "items": ["https://example.com"],
    }

    stage_input = StageInput(
        stage_name="subdomains",
        stage_index=1,
        stage_total=4,
        pipeline=pipeline_input,
        state_snapshot=external_snapshot,
    )

    external_snapshot["counts"]["urls"] = 999
    external_snapshot["items"].append("https://mutated.example.com")

    frozen_snapshot = stage_input.to_dict()["state_snapshot"]
    assert frozen_snapshot["counts"]["urls"] == 1
    assert frozen_snapshot["items"] == ["https://example.com"]

    with pytest.raises(TypeError):
        stage_input.state_snapshot["new"] = "value"  # type: ignore[index]


@pytest.mark.unit
def test_stage_output_maps_state_to_stage_outcome() -> None:
    completed = StageOutput.from_stage_state(
        stage_name="urls",
        state="COMPLETED",
        duration_seconds=1.25,
        metrics={"retry_count": 1},
    )
    failed = StageOutput.from_stage_state(
        stage_name="urls",
        state="FAILED",
        duration_seconds=2.5,
        metrics={"error": "boom"},
    )
    skipped = StageOutput.from_stage_state(
        stage_name="urls",
        state="SKIPPED",
        duration_seconds=0.0,
    )

    assert completed.outcome == StageOutcome.COMPLETED
    assert failed.outcome == StageOutcome.FAILED
    assert skipped.outcome == StageOutcome.SKIPPED
    assert completed.retry_count == 1
    assert failed.error == "boom"


@pytest.mark.unit
def test_stage_output_tolerates_non_deepcopyable_metric_payloads() -> None:
    class _MetricPayload:
        def __init__(self) -> None:
            self.metadata = MappingProxyType({"tool": "httpx", "status": "ok"})

    output = StageOutput.from_stage_state(
        stage_name="live_hosts",
        state="COMPLETED",
        duration_seconds=0.8,
        metrics={"details": {"payload": _MetricPayload()}},
    )

    details = output.to_dict()["metrics"]["details"]
    assert isinstance(details["payload"], dict)
    assert details["payload"]["metadata"]["tool"] == "httpx"

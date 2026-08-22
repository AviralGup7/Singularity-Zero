"""Stage outcome classification: do not emit completed after fail/skip."""

from __future__ import annotations

from types import SimpleNamespace

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.pipeline.services.pipeline_orchestrator.orchestrator import stage_progress_kind


def _ctx(*, status: str = "", metric_status: str = "", reason: str = "") -> SimpleNamespace:
    metrics = {}
    if metric_status or reason:
        metrics = {"status": metric_status, "reason": reason}
    return SimpleNamespace(
        result=SimpleNamespace(
            stage_status={"nuclei": status} if status else {},
            module_metrics={"nuclei": metrics} if metrics else {},
        )
    )


def test_stage_progress_kind_failed_does_not_look_completed() -> None:
    ctx = _ctx(status="FAILED")
    assert stage_progress_kind(ctx, "nuclei", None) == "failed"


def test_stage_progress_kind_skipped_from_retry_output() -> None:
    ctx = _ctx(status="SKIPPED_DISABLED", metric_status="skipped", reason="circuit_breaker_open")
    output = StageOutput(stage_name="nuclei", outcome=StageOutcome.SKIPPED, duration_seconds=0.0)
    assert stage_progress_kind(ctx, "nuclei", output) == "skipped"


def test_stage_progress_kind_completed_only_when_clean() -> None:
    ctx = _ctx(status="COMPLETED", metric_status="ok")
    output = StageOutput(stage_name="nuclei", outcome=StageOutcome.COMPLETED, duration_seconds=1.0)
    assert stage_progress_kind(ctx, "nuclei", output) == "completed"


def test_stage_progress_kind_error_metric_wins_over_missing_status() -> None:
    ctx = _ctx(metric_status="error")
    assert stage_progress_kind(ctx, "nuclei", None) == "failed"

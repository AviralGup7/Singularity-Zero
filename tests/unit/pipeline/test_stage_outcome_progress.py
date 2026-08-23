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


def test_execute_single_stage_does_not_emit_completed_after_failure() -> None:
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    from src.pipeline.services.pipeline_orchestrator.orchestrator import PipelineOrchestrator

    orch = PipelineOrchestrator()
    orch._emit_event = MagicMock()
    orch._build_stage_input_contract = MagicMock(return_value={})
    orch._resolve_stage_timeout = MagicMock(return_value=1)
    orch._record_stage_post_run = AsyncMock()
    orch._run_stage_with_retry = AsyncMock(return_value=None)

    ctx = _ctx(status="FAILED", metric_status="error")
    ctx.result.cancel_requested = False
    emitted: list[str] = []

    def progress_emitter(stage: str, message: str, percent: int, **fields: object) -> None:
        emitted.append(str(fields.get("status") or fields.get("stage_status") or ""))

    result = asyncio.run(
        orch._execute_single_stage(
            "nuclei",
            MagicMock(),
            SimpleNamespace(),
            SimpleNamespace(),
            ctx,
            None,
            SimpleNamespace(load_stage_deltas=lambda _name: []),
            _CheckpointGuard,
            progress_emitter,
            MagicMock(),
        )
    )
    assert result == 1
    assert "completed" not in emitted
    assert "running" in emitted


class _CheckpointGuard:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def __enter__(self) -> _CheckpointGuard:
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

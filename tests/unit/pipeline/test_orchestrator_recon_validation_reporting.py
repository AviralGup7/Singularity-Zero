from src.core.models.stage_result import PipelineContext, StageStatus
from src.pipeline.services.pipeline_orchestrator._run_execution import (
    _collect_failed_stages,
    _validate_recon_outputs,
)


def test_recon_validation_failure_does_not_emit_blank_urls_failure_reason() -> None:
    ctx = PipelineContext()
    ctx.result.apply_state_delta({"subdomains": ["api.example.com"]})
    ctx.result.live_hosts = set()
    # urls is empty by default in a new context
    ctx.result.stage_status["urls"] = StageStatus.COMPLETED.value
    ctx.result.module_metrics["urls"] = {
        "status": "warning",
        "details": {"live_host_count": 0, "source_contribution_count": 0},
        "fatal": False,
    }

    _validate_recon_outputs(ctx)
    failed_stages = _collect_failed_stages(ctx)

    assert ctx.result.stage_status["urls"] == StageStatus.COMPLETED.value
    assert ctx.result.stage_status["recon_validation"] == StageStatus.FAILED.value
    assert failed_stages == [
        ("recon_validation", "Pipeline finished recon without discoverable URLs."),
    ]


def test_collect_failed_stages_ignores_explicit_non_fatal_timeout() -> None:
    ctx = PipelineContext()
    ctx.result.stage_status["intelligence"] = StageStatus.FAILED.value
    ctx.result.module_metrics["intelligence"] = {
        "status": "timeout",
        "failure_reason": "Stage intelligence timed out after 180s",
        "fatal": False,
    }

    failed_stages = _collect_failed_stages(ctx)

    assert failed_stages == []


def test_collect_failed_stages_keeps_fatal_timeout_failures() -> None:
    ctx = PipelineContext()
    ctx.result.stage_status["urls"] = StageStatus.FAILED.value
    ctx.result.module_metrics["urls"] = {
        "status": "timeout",
        "failure_reason": "Stage urls timed out after 120s",
        "fatal": True,
    }

    failed_stages = _collect_failed_stages(ctx)

    assert failed_stages == [("urls", "Stage urls timed out after 120s")]

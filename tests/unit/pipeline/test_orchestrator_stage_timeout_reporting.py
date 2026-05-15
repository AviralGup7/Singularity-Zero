import argparse
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import cast

import pytest

from src.core.models.stage_result import PipelineContext
from src.pipeline.retry import RetryPolicy
from src.pipeline.services.pipeline_orchestrator import orchestrator as orch_mod
from src.pipeline.services.pipeline_orchestrator._run_execution import resolve_pipeline_exit_code
from src.pipeline.services.pipeline_orchestrator.orchestrator import PipelineOrchestrator


@pytest.mark.asyncio
async def test_run_stage_with_retry_reports_non_empty_timeout_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress_events: list[dict[str, object]] = []

    def _capture_progress(stage: str, message: str, percent: int, **meta: object) -> None:
        event: dict[str, object] = {
            "stage": stage,
            "message": message,
            "percent": percent,
        }
        for key, value in meta.items():
            event[str(key)] = value
        progress_events.append(event)

    monkeypatch.setattr(orch_mod, "emit_progress", _capture_progress)

    orchestrator = PipelineOrchestrator()

    def _fixed_policy(_config: object) -> RetryPolicy:
        return RetryPolicy(
            max_attempts=1,
            initial_backoff_seconds=0.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            retry_on_timeout=True,
            retry_on_error=True,
            jitter_factor=0.0,
        )

    monkeypatch.setattr(orchestrator, "_get_stage_retry_policy", _fixed_policy)

    async def _slow_stage(
        _args: argparse.Namespace, _config: object, _ctx: PipelineContext
    ) -> None:
        await orch_mod.asyncio.sleep(0.05)

    ctx = PipelineContext()
    run_stage_with_retry = cast(
        Callable[..., Awaitable[None]],
        getattr(orchestrator, "_run_stage_with_retry"),
    )

    await run_stage_with_retry(
        stage_name="active_scan",
        method=_slow_stage,
        args=argparse.Namespace(),
        config=SimpleNamespace(),
        ctx=ctx,
        timeout=0,
        scope_interceptor=None,
    )

    stage_metrics = ctx.result.module_metrics.get("active_scan", {})
    stage_error = str(stage_metrics.get("error", ""))

    assert stage_error
    assert "timed out" in stage_error.lower()
    assert stage_metrics.get("fatal") is False

    failed_events = [
        event
        for event in progress_events
        if str(event.get("event_trigger", "")) == "stage_failed"
        and str(event.get("stage", "")) == "active_scan"
    ]
    assert failed_events
    failure_reason = str(failed_events[-1].get("failure_reason", ""))
    assert failure_reason
    assert "timed out" in failure_reason.lower()


@pytest.mark.asyncio
async def test_run_stage_with_retry_marks_recon_timeout_as_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    orchestrator = PipelineOrchestrator()

    def _fixed_policy(_config: object) -> RetryPolicy:
        return RetryPolicy(
            max_attempts=1,
            initial_backoff_seconds=0.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            retry_on_timeout=True,
            retry_on_error=True,
            jitter_factor=0.0,
        )

    monkeypatch.setattr(orchestrator, "_get_stage_retry_policy", _fixed_policy)

    async def _slow_stage(
        _args: argparse.Namespace, _config: object, _ctx: PipelineContext
    ) -> None:
        await orch_mod.asyncio.sleep(0.05)

    ctx = PipelineContext()
    run_stage_with_retry = cast(
        Callable[..., Awaitable[None]],
        getattr(orchestrator, "_run_stage_with_retry"),
    )

    await run_stage_with_retry(
        stage_name="urls",
        method=_slow_stage,
        args=argparse.Namespace(),
        config=SimpleNamespace(),
        ctx=ctx,
        timeout=0,
        scope_interceptor=None,
    )

    stage_metrics = ctx.result.module_metrics.get("urls", {})
    assert stage_metrics.get("status") == "timeout"
    assert stage_metrics.get("fatal") is True


def test_resolve_stage_timeout_scales_urls_for_large_live_hosts() -> None:
    orchestrator = PipelineOrchestrator()
    ctx = PipelineContext()
    ctx.result.live_hosts = {f"https://h{i}.example.com" for i in range(1300)}

    timeout = orchestrator._resolve_stage_timeout(
        stage_name="urls",
        config=SimpleNamespace(filters={}),
        ctx=ctx,
    )

    assert timeout == 1800


def test_resolve_stage_timeout_scales_live_hosts_for_large_subdomain_sets() -> None:
    orchestrator = PipelineOrchestrator()
    ctx = PipelineContext()
    ctx.result.subdomains = {f"h{i}.example.com" for i in range(4000)}

    timeout = orchestrator._resolve_stage_timeout(
        stage_name="live_hosts",
        config=SimpleNamespace(
            filters={},
            tools={"httpx": True},
            httpx={"batch_size": 400, "batch_concurrency": 2, "timeout_seconds": 120},
        ),
        ctx=ctx,
    )

    assert timeout == 2400


def test_resolve_stage_timeout_caps_extreme_live_hosts_runtime_projection() -> None:
    orchestrator = PipelineOrchestrator()
    ctx = PipelineContext()
    ctx.result.subdomains = {f"h{i}.example.com" for i in range(22000)}

    timeout = orchestrator._resolve_stage_timeout(
        stage_name="live_hosts",
        config=SimpleNamespace(
            filters={},
            tools={"httpx": True},
            httpx={"batch_size": 400, "batch_concurrency": 1, "timeout_seconds": 120},
        ),
        ctx=ctx,
    )

    assert timeout == 7200


def test_resolve_stage_timeout_accounts_for_live_hosts_retry_budget() -> None:
    orchestrator = PipelineOrchestrator()
    ctx = PipelineContext()
    ctx.result.subdomains = {f"h{i}.example.com" for i in range(4000)}

    timeout = orchestrator._resolve_stage_timeout(
        stage_name="live_hosts",
        config=SimpleNamespace(
            filters={},
            tools={"httpx": True, "retry_attempts": 3},
            httpx={"batch_size": 400, "batch_concurrency": 2, "timeout_seconds": 120},
        ),
        ctx=ctx,
    )

    assert timeout > 2400


def test_resolve_stage_timeout_honors_filter_overrides() -> None:
    orchestrator = PipelineOrchestrator()
    ctx = PipelineContext()

    timeout = orchestrator._resolve_stage_timeout(
        stage_name="urls",
        config=SimpleNamespace(
            filters={
                "urls_stage_timeout_seconds": 1500,
                "stage_timeout_overrides": {"urls": 2100},
            }
        ),
        ctx=ctx,
    )

    assert timeout == 2100


def test_resolve_pipeline_exit_code_ignores_warning_only_recon_degradation() -> None:
    orchestrator = PipelineOrchestrator()
    ctx = PipelineContext()
    ctx.result.urls = {"https://example.com"}
    ctx.result.module_metrics["urls"] = {
        "status": "timeout",
        "fatal": False,
        "failure_reason": "Provider timeout degraded gracefully",
    }

    exit_code = resolve_pipeline_exit_code(
        orchestrator,
        ctx=ctx,
        config=SimpleNamespace(target_name="example.com"),
        started_at=0.0,
        progress_emitter=lambda *_args, **_kwargs: None,
    )

    assert exit_code == 0

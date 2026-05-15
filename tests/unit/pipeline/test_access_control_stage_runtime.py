import asyncio
from importlib import import_module
from types import SimpleNamespace
from typing import Any

import pytest

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_orchestrator.stages import access_control as stage

analyzer_module = import_module("src.analysis.checks.active.access_control_analyzer")


@pytest.mark.asyncio
async def test_access_control_stage_uses_adapter_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake_analyze_access_control_async(
        endpoints: list[dict[str, object]],
        response_cache: object | None = None,
        limit: int = 20,
        **kwargs: Any,
    ) -> list[dict[str, object]]:
        _ = kwargs
        await asyncio.sleep(0)
        captured["endpoints"] = endpoints
        captured["response_cache"] = response_cache
        captured["limit"] = limit
        return [
            {
                "url": "https://example.com/admin",
                "severity": "high",
                "confidence": 0.8,
                "category": "access_control",
                "title": "Bypass indicator",
            }
        ]

    def fail_sync_wrapper(*args: object, **kwargs: object) -> list[dict[str, object]]:
        _ = (args, kwargs)
        raise RuntimeError(
            "check_endpoints cannot be called from a running event loop; "
            "use 'await analyze_endpoints(...)' instead"
        )

    monkeypatch.setattr(
        analyzer_module,
        "analyze_access_control_async",
        fake_analyze_access_control_async,
    )
    monkeypatch.setattr(analyzer_module, "analyze_access_control", fail_sync_wrapper)
    monkeypatch.setattr(stage, "_build_access_control_cache", lambda config: object())

    ctx = PipelineContext()
    ctx.result.urls = {"https://example.com/admin", "/relative"}
    ctx.result.selected_priority_items = []

    output = await stage.run_access_control_testing(
        args=None,
        config=SimpleNamespace(analysis={}),
        ctx=ctx,
    )

    assert isinstance(output, StageOutput)
    assert output.stage_name == "access_control"
    assert output.outcome == StageOutcome.COMPLETED

    # Verify findings are in state_delta (not directly mutated onto ctx.result)
    state_findings = output.state_delta.get("reportable_findings", [])
    assert len(state_findings) == 1
    assert state_findings[0]["url"] == "https://example.com/admin"

    # Verify module_metrics in state_delta
    metrics = output.state_delta.get("module_metrics", {}).get("access_control", {})
    assert metrics["status"] == "ok"
    assert metrics["findings_count"] == 1

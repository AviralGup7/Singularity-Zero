from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.contracts.schema_validator import SchemaValidationError
from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_orchestrator.stages import analysis as stage


class _DummyOutputStore:
    def __init__(self, cache_root: Path) -> None:
        self.cache_root = cache_root


@pytest.mark.asyncio
async def test_passive_scan_does_not_retry_deterministic_contract_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    call_counter = {"count": 0}

    def failing_run_passive_scanners(
        *args: object, **kwargs: object
    ) -> tuple[dict[str, list[dict[str, object]]], dict[str, object]]:
        _ = (args, kwargs)
        call_counter["count"] += 1
        raise SchemaValidationError(
            "detection payload.logging_failure_detector[0].url must be an absolute URL"
        )

    monkeypatch.setattr(stage, "run_passive_scanners", failing_run_passive_scanners)
    monkeypatch.setattr(
        stage, "execute_validation_runtime", lambda *a, **k: {"results": {}, "errors": []}
    )
    monkeypatch.setattr(stage, "merge_findings", lambda *a, **k: [])
    monkeypatch.setattr(stage, "filter_reportable_findings", lambda findings: findings)
    monkeypatch.setattr(stage, "annotate_finding_history", lambda previous, findings: findings)
    monkeypatch.setattr(stage, "annotate_finding_decisions", lambda findings: findings)
    monkeypatch.setattr(stage, "apply_lifecycle", lambda findings: findings)

    ctx = PipelineContext()
    ctx.output_store = _DummyOutputStore(tmp_path)
    ctx.result.live_hosts = {"https://example.com"}
    ctx.result.urls = {"https://example.com/account"}
    ctx.result.deep_analysis_urls = ["https://example.com/account"]

    config = SimpleNamespace(
        analysis={"max_iteration_limit": 1, "finding_feedback_limit": 10},
        extensions={},
        mode="safe",
    )

    output = await stage.run_passive_scanning(args=None, config=config, ctx=ctx)

    assert call_counter["count"] == 1
    assert output.metrics["passive_scan"]["deterministic_contract_failures"] == 1
    assert output.metrics["passive_scan"]["attempts"] == 1

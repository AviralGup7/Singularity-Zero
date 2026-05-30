from __future__ import annotations

import pytest

from src.execution.active_manifest import (
    ActiveCapability,
    ActiveCheckManifest,
    ActiveExecutionBudget,
    ActiveInputKind,
    ActiveIOContract,
    ActiveResultEncoding,
    get_active_manifest,
    query_active_manifests,
)
from src.execution.isolated import (
    _isolated_test_return_findings,
    _isolated_test_sleep_forever,
    run_callable_isolated,
)
from src.pipeline.services.pipeline_orchestrator.stages.probe_registry import _build_response_cache
from src.pipeline.services.pipeline_orchestrator.stages.probe_runners import _try_probe


def _test_manifest(timeout: float) -> ActiveCheckManifest:
    return ActiveCheckManifest(
        check_id="unit_hard_wall",
        display_name="Unit hard wall",
        io=ActiveIOContract(
            input_kind=ActiveInputKind.URLS,
            input_schema="unit.urls.v1",
            output_schema="unit.findings.v1",
            result_encoding=ActiveResultEncoding.FINDINGS_JSON,
        ),
        required_capabilities=frozenset({ActiveCapability.PAYLOAD_GENERATION}),
        budget=ActiveExecutionBudget(timeout_seconds=timeout, memory_mb=64),
    )


def test_default_active_manifests_are_capability_queryable() -> None:
    manifest = get_active_manifest("xss")

    assert manifest.io.result_encoding == ActiveResultEncoding.FINDINGS_JSON
    assert ActiveCapability.RESPONSE_CACHE in manifest.required_capabilities
    assert manifest.budget.timeout_seconds > 0

    payload_generators = query_active_manifests(capability=ActiveCapability.PAYLOAD_GENERATION)
    assert {item.check_id for item in payload_generators} >= {"mutation", "fuzzing_suggestions"}


def test_isolated_runner_returns_child_result() -> None:
    result = run_callable_isolated(_isolated_test_return_findings, (), {}, _test_manifest(5.0))

    assert result.ok is True
    assert result.value == [{"url": "https://example.com", "severity": "info"}]
    assert result.manifest is not None
    assert result.manifest["budget"]["timeout_seconds"] == 5.0


def test_isolated_runner_kills_infinite_loop_at_budget_wall() -> None:
    result = run_callable_isolated(_isolated_test_sleep_forever, (), {}, _test_manifest(0.2))

    assert result.ok is False
    assert result.reason == "timeout"
    assert result.killed is True
    assert result.duration_seconds < 2.0


@pytest.mark.asyncio
async def test_try_probe_replaces_unpicklable_response_cache_for_child_process() -> None:
    name, findings, ok = await _try_probe(
        "sqli",
        _isolated_test_return_findings,
        [{"url": "https://example.com"}],
        _build_response_cache(),
        timeout_seconds=5.0,
    )

    assert name == "sqli"
    assert ok is True
    assert findings == [{"url": "https://example.com", "severity": "info"}]

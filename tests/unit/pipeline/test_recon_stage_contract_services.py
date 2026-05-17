import json
from types import MappingProxyType, SimpleNamespace

import pytest

from src.core.contracts.pipeline_runtime import PipelineInput, StageInput, StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_orchestrator.orchestrator import PipelineOrchestrator
from src.pipeline.services.pipeline_orchestrator.stages import recon as recon_stage
from src.pipeline.services.services import recon_service
from src.recon.scoring import resolve_priority_limit


class _DummyOutputStore:
    def __init__(self) -> None:
        self.parameters_written: set[str] = set()
        self.priority_written: list[str] = []

    def write_parameters(self, parameters: set[str]) -> None:
        self.parameters_written = set(parameters)

    def write_priority_endpoints(self, priority_urls: list[str]) -> None:
        self.priority_written = list(priority_urls)


@pytest.mark.asyncio
async def test_subdomain_enumeration_filters_sensitive_wildcard_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recon_service,
        "enumerate_subdomains",
        lambda scope_entries, runtime, skip_crtsh: {
            "api.example.com",
            "git.example.com",
            "vault.example.com",
        },
    )
    stage_input = StageInput(
        stage_name="subdomains",
        stage_index=1,
        stage_total=3,
        pipeline=PipelineInput(
            target_name="example.com",
            scope_entries=("*.example.com",),
            run_id="run-1",
        ),
        state_snapshot={"result": {"discovery_enabled": True, "use_cache": False}},
        runtime={},
    )

    output = await recon_service.run_subdomain_enumeration_service(stage_input)

    assert output.outcome == StageOutcome.COMPLETED
    assert output.state_delta["subdomains"] == {"api.example.com"}
    details = output.metrics["details"]
    assert details["sensitive_scope_excluded_count"] == 2
    assert list(details["sensitive_scope_excluded"]) == ["git.example.com", "vault.example.com"]


@pytest.mark.asyncio
async def test_subdomain_enumeration_keeps_explicit_sensitive_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recon_service,
        "enumerate_subdomains",
        lambda scope_entries, runtime, skip_crtsh: {"git.example.com"},
    )
    stage_input = StageInput(
        stage_name="subdomains",
        stage_index=1,
        stage_total=3,
        pipeline=PipelineInput(
            target_name="example.com",
            scope_entries=("*.example.com", "git.example.com"),
            run_id="run-1",
        ),
        state_snapshot={"result": {"discovery_enabled": True, "use_cache": False}},
        runtime={},
    )

    output = await recon_service.run_subdomain_enumeration_service(stage_input)

    assert output.outcome == StageOutcome.COMPLETED
    assert output.state_delta["subdomains"] == {"git.example.com"}


@pytest.mark.asyncio
async def test_run_parameter_extraction_stage_returns_state_delta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recon_service, "extract_parameters", lambda urls: {"id", "token"})
    monkeypatch.setattr(recon_service, "infer_target_profile", lambda urls: {"stack": "flask"})
    monkeypatch.setattr(recon_service, "load_history_feedback", lambda previous: {"known": True})

    stage_input = StageInput(
        stage_name="parameters",
        stage_index=1,
        stage_total=3,
        pipeline=PipelineInput(
            target_name="example.com", scope_entries=("example.com",), run_id="run-1"
        ),
        state_snapshot={
            "result": {
                "urls": ["https://example.com?a=1", "https://example.com/b?token=abc"],
                "previous_run": None,
            }
        },
        runtime={},
    )

    output = await recon_service.run_parameter_extraction_stage(stage_input)

    assert output.outcome == StageOutcome.COMPLETED
    assert sorted(output.state_delta["parameters"]) == ["id", "token"]
    assert output.state_delta["target_profile"]["stack"] == "flask"


@pytest.mark.asyncio
async def test_run_priority_ranking_stage_allows_zero_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recon_service,
        "rank_urls",
        lambda urls, filters, scoring, mode, target_profile, history_feedback: [
            {"url": "https://example.com/a", "score": 10}
        ],
    )
    monkeypatch.setattr(
        recon_service,
        "select_deep_analysis_targets",
        lambda ranked, analysis, mode: ([], {"selected_count": 0}),
    )

    stage_input = StageInput(
        stage_name="ranking",
        stage_index=2,
        stage_total=3,
        pipeline=PipelineInput(
            target_name="example.com",
            scope_entries=("example.com",),
            run_id="run-1",
        ),
        state_snapshot={
            "result": {
                "urls": ["https://example.com/a"],
                "target_profile": {},
                "history_feedback": {},
            }
        },
        runtime={"filters": {}, "scoring": {}, "analysis": {}, "mode": "safe"},
    )

    output = await recon_service.run_priority_ranking_stage(stage_input)

    assert output.outcome == StageOutcome.COMPLETED
    assert output.metrics["selected_for_deep_analysis"] == 0
    assert output.artifacts["deep_analysis_url_count"] == 0


@pytest.mark.asyncio
async def test_run_priority_ranking_stage_handles_tuple_history_feedback() -> None:
    stage_input = StageInput(
        stage_name="ranking",
        stage_index=2,
        stage_total=3,
        pipeline=PipelineInput(
            target_name="example.com",
            scope_entries=("example.com",),
            run_id="run-1",
        ),
        state_snapshot={
            "result": {
                "urls": ["https://example.com/account?id=1"],
                "target_profile": {},
                "history_feedback": {
                    "hosts": ("example.com",),
                    "endpoint_keys": (),
                    "endpoint_bases": (),
                    "parameter_names": ("id",),
                },
            }
        },
        runtime={"filters": {}, "scoring": {}, "analysis": {}, "mode": "safe"},
    )

    output = await recon_service.run_priority_ranking_stage(stage_input)

    assert output.outcome == StageOutcome.COMPLETED
    assert output.artifacts["priority_url_count"] >= 1


@pytest.mark.asyncio
async def test_run_parameter_extraction_stage_accepts_string_previous_run(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recon_service, "extract_parameters", lambda urls: {"id"})
    monkeypatch.setattr(recon_service, "infer_target_profile", lambda urls: {"stack": "flask"})

    previous_run = tmp_path / "previous"
    previous_run.mkdir()
    (previous_run / "findings.json").write_text(
        json.dumps(
            [
                {
                    "decision": "KEEP",
                    "severity": "high",
                    "url": "https://example.com/account?id=1",
                }
            ]
        ),
        encoding="utf-8",
    )

    stage_input = StageInput(
        stage_name="parameters",
        stage_index=1,
        stage_total=3,
        pipeline=PipelineInput(
            target_name="example.com", scope_entries=("example.com",), run_id="run-1"
        ),
        state_snapshot={
            "result": {
                "urls": ["https://example.com/account?id=1"],
                "previous_run": str(previous_run),
            }
        },
        runtime={},
    )

    output = await recon_service.run_parameter_extraction_stage(stage_input)

    assert output.outcome == StageOutcome.COMPLETED
    history_feedback = output.state_delta["history_feedback"]
    assert "example.com" in history_feedback["hosts"]
    assert "id" in history_feedback["parameter_names"]


def test_resolve_priority_limit_accepts_mappingproxy_priority_config() -> None:
    filters = {
        "priority_limit": MappingProxyType(
            {
                "default": 11,
                "safe": 7,
            }
        )
    }

    assert resolve_priority_limit(filters, "safe", {"total_urls": 10}) == 7
    assert resolve_priority_limit(filters, "aggressive", {"total_urls": 10}) == 11


@pytest.mark.unit
def test_orchestrator_merges_stage_output_delta_into_context() -> None:
    ctx = PipelineContext(output_store=_DummyOutputStore())
    orchestrator = PipelineOrchestrator()

    output = StageOutput(
        stage_name="parameters",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=1.2,
        metrics={"status": "ok"},
        state_delta={
            "parameters": ["id", "token"],
            "target_profile": {"framework": "fastapi"},
            "history_feedback": {"baseline": 2},
        },
    )

    orchestrator._merge_stage_output(ctx, "parameters", output)

    assert ctx.result.parameters == {"id", "token"}
    assert ctx.result.target_profile["framework"] == "fastapi"
    assert ctx.result.module_metrics["parameters"]["status"] == "ok"
    assert ctx.result.stage_status["parameters"] == "COMPLETED"
    assert ctx.output_store.parameters_written == {"id", "token"}


@pytest.mark.asyncio
async def test_stage_wrapper_returns_output_without_mutating_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_service(stage_input: StageInput) -> StageOutput:
        return StageOutput(
            stage_name="parameters",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.1,
            state_delta={
                "parameters": ["api_key"],
                "target_profile": {"framework": "django"},
                "history_feedback": {"seen": 1},
            },
        )

    monkeypatch.setattr(recon_stage, "run_parameter_extraction_stage", _fake_service)

    ctx = PipelineContext(output_store=_DummyOutputStore())
    ctx.result.urls = {"https://example.com?a=1"}

    output = await recon_stage.run_parameter_extraction(
        args=SimpleNamespace(),
        config=SimpleNamespace(
            target_name="example.com", filters={}, scoring={}, analysis={}, mode="default"
        ),
        ctx=ctx,
    )

    assert isinstance(output, StageOutput)
    assert ctx.result.parameters == set()


@pytest.mark.asyncio
async def test_parameter_wrapper_avoids_success_progress_when_stage_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _failed_stage(stage_input: StageInput) -> StageOutput:
        return StageOutput(
            stage_name="parameters",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.01,
            error="boom",
            reason="parameter_extraction_failed",
        )

    progress_messages: list[str] = []

    def _capture_progress(stage: str, message: str, percent: int, **kwargs: object) -> None:
        progress_messages.append(message)

    monkeypatch.setattr(recon_stage, "run_parameter_extraction_stage", _failed_stage)
    monkeypatch.setattr(recon_stage, "emit_progress", _capture_progress)

    ctx = PipelineContext(output_store=_DummyOutputStore())
    ctx.result.urls = {"https://example.com/account?id=1"}

    output = await recon_stage.run_parameter_extraction(
        args=SimpleNamespace(),
        config=SimpleNamespace(
            target_name="example.com",
            filters={},
            scoring={},
            analysis={},
            mode="safe",
        ),
        ctx=ctx,
    )

    assert output.outcome == StageOutcome.FAILED
    assert "Extracting parameters" in progress_messages
    assert not any(message.startswith("Extracted ") for message in progress_messages)


@pytest.mark.asyncio
async def test_ranking_wrapper_avoids_success_progress_when_stage_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _failed_stage(stage_input: StageInput) -> StageOutput:
        return StageOutput(
            stage_name="ranking",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.01,
            error="boom",
            reason="priority_ranking_failed",
        )

    progress_messages: list[str] = []

    def _capture_progress(stage: str, message: str, percent: int, **kwargs: object) -> None:
        progress_messages.append(message)

    monkeypatch.setattr(recon_stage, "run_priority_ranking_stage", _failed_stage)
    monkeypatch.setattr(recon_stage, "emit_progress", _capture_progress)

    ctx = PipelineContext(output_store=_DummyOutputStore())
    ctx.result.urls = {"https://example.com/account?id=1"}

    output = await recon_stage.run_priority_ranking(
        args=SimpleNamespace(),
        config=SimpleNamespace(
            target_name="example.com",
            filters={},
            scoring={},
            analysis={},
            mode="safe",
        ),
        ctx=ctx,
    )

    assert output.outcome == StageOutcome.FAILED
    assert "Scoring priority endpoints" in progress_messages
    assert not any(message.startswith("Ranked ") for message in progress_messages)

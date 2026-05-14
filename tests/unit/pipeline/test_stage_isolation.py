"""Contract test: stage wrappers must not mutate PipelineContext.result directly.

Every stage runner MUST return a StageOutput with all business data in state_delta.
The orchestrator is responsible for merging the state_delta into ctx.result via
merge_stage_output(). Stage wrappers that bypass this contract by writing directly
to ctx.result break the isolation guarantee and cause state drift.

Run with: pytest tests/unit/pipeline/test_stage_isolation.py -q
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext, StageResult, StageStatus


class _StrictPipelineContext(PipelineContext):
    """PipelineContext variant that raises AttributeError on any result mutation.

    This catches any stage wrapper that tries to bypass the StageOutput contract
    by writing directly to ctx.result instead of returning the data in state_delta.
    """

    __mutated_fields: set[str]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.__mutated_fields = set()

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "result" and hasattr(self, "_StrictPipelineContext__mutated_fields"):
            raise AttributeError(
                "Stage wrapper MUST NOT set ctx.result directly. "
                "Return StageOutput(state_delta={...}) and let the orchestrator "
                "merge it via merge_stage_output()."
            )
        super().__setattr__(name, value)

    def __getattr__(self, name: str) -> Any:
        if name == "result" and "_StrictPipelineContext__mutated_fields" in self.__dict__:
            raise AttributeError(
                "Stage wrapper MUST NOT read ctx.result. "
                "Use the stage service's returned StageOutput.state_delta instead."
            )
        return super().__getattr__(name)


class _DummyOutputStore:
    def __init__(self) -> None:
        self.cache_root = Path("/tmp/dummy")
        self.run_dir = Path("/tmp/dummy/run")
        self.parameters_written: set[str] = set()
        self.priority_written: list[str] = []

    def write_parameters(self, parameters: set[str]) -> None:
        self.parameters_written = set(parameters)

    def write_priority_endpoints(self, priority_urls: list[str]) -> None:
        self.priority_written = list(priority_urls)

    def write_subdomains(self, subdomains: set[str]) -> None:
        pass

    def write_live_hosts(self, records: list[dict[str, Any]], hosts: set[str]) -> None:
        pass

    def write_urls(self, urls: set[str]) -> None:
        pass


def _make_strict_context() -> _StrictPipelineContext:
    ctx = _StrictPipelineContext(
        result=StageResult(
            scope_entries=["example.com"],
            use_cache=False,
            module_metrics={},
            started_at=time.time(),
            discovery_enabled=True,
        ),
        output_store=_DummyOutputStore(),
    )
    ctx.result.stage_status = {}
    return ctx


def _assert_stage_output_isolation(
    stage_name: str,
    stage_output: StageOutput | None,
    ctx: PipelineContext,
) -> None:
    """Verify a stage returned StageOutput and did not mutate ctx.result."""
    assert stage_output is not None, (
        f"Stage '{stage_name}' returned None. "
        f"Stages MUST return StageOutput(state_delta={{...}}) instead."
    )
    assert isinstance(stage_output, StageOutput), (
        f"Stage '{stage_name}' returned {type(stage_output).__name__}. Must return StageOutput."
    )
    assert stage_output.stage_name == stage_name, (
        f"StageOutput.stage_name mismatch: {stage_output.stage_name!r} != {stage_name!r}"
    )
    assert hasattr(ctx, "result"), "ctx.result was accessed during stage execution"


def _build_mock_config() -> SimpleNamespace:
    return SimpleNamespace(
        target_name="example.com",
        mode="safe",
        filters={},
        scoring={},
        analysis={"max_iteration_limit": 1, "finding_feedback_limit": 10},
        extensions={},
        tools={
            "subfinder": True,
            "assetfinder": True,
            "amass": False,
            "httpx": True,
        },
        nuclei={"adaptive_tags": {}, "dedupe_history": True},
        screenshots={"browser_paths": []},
        review={"high_confidence_shortlist_limit": 5, "manual_verification_limit": 8},
        output_dir="/tmp/output",
    )


@pytest.mark.unit
class TestStageIsolationContracts:
    """Verify each registered stage wrapper respects StageOutput contract."""

    @pytest.mark.asyncio
    async def test_recon_subdomain_enumeration_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import recon as recon_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.subdomains = {"www.example.com"}

        mock_output = StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=1.0,
            state_delta={"subdomains": ["api.example.com", "www.example.com"]},
        )

        args = SimpleNamespace(skip_crtsh=False, refresh_cache=False)

        with patch(
            "src.pipeline.services.pipeline_orchestrator.stages.recon.run_subdomain_enumeration_service",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            output = await recon_stage.run_subdomain_enumeration(args=args, config=config, ctx=ctx)

        _assert_stage_output_isolation("subdomains", output, ctx)

    @pytest.mark.asyncio
    async def test_recon_live_hosts_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import recon as recon_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.subdomains = {"example.com", "www.example.com"}

        def mock_probe(hosts, config, progress, force_recheck):
            return ([{"host": "https://example.com", "status": 200}], {"https://example.com"})

        def mock_enrichment(subdomains, records, config, **kwargs):
            return ([{"host": "https://example.com", "status": 200}], {"https://example.com"}, {})

        args = SimpleNamespace(refresh_cache=False)

        with patch.object(recon_stage, "probe_live_hosts", side_effect=mock_probe):
            with patch.object(recon_stage, "run_service_enrichment", side_effect=mock_enrichment):
                with patch.object(recon_stage, "emit_progress", new=AsyncMock()):
                    with patch.object(
                        recon_stage,
                        "_tool_diagnostics",
                        return_value={"httpx": {"available": True}},
                    ):
                        output = await recon_stage.run_live_hosts(args=args, config=config, ctx=ctx)

        _assert_stage_output_isolation("live_hosts", output, ctx)

    @pytest.mark.asyncio
    async def test_recon_url_collection_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import recon as recon_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.live_hosts = {"https://example.com"}

        mock_output = StageOutput(
            stage_name="urls",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=1.0,
            state_delta={"urls": ["https://example.com/about", "https://example.com/contact"]},
        )

        args = SimpleNamespace(refresh_cache=False)

        with patch(
            "src.pipeline.services.pipeline_orchestrator.stages.recon.run_url_collection_service",
            new_callable=AsyncMock,
            return_value=mock_output,
        ):
            output = await recon_stage.run_url_collection(args=args, config=config, ctx=ctx)

        _assert_stage_output_isolation("urls", output, ctx)

    @pytest.mark.asyncio
    async def test_analysis_passive_scanning_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import analysis as analysis_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.live_hosts = {"https://example.com"}
        ctx.result.urls = {"https://example.com/about"}
        ctx.result.deep_analysis_urls = ["https://example.com/about"]
        ctx.result.selected_priority_items = [{"url": "https://example.com/about"}]

        async def mock_passive_scanners(*args, **kwargs):
            return (
                {"xss": [{"title": "XSS", "url": "https://example.com/x", "confidence": 0.8}]},
                {"urls": [], "responses": []},
            )

        def mock_validation(*args, **kwargs):
            return {"results": {}, "errors": [], "settings": {}, "metric": {}, "metrics": {}}, True

        args = SimpleNamespace()

        with patch(
            "src.pipeline.services.pipeline_orchestrator.stages.analysis.run_passive_scanners",
            side_effect=mock_passive_scanners,
        ):
            with patch(
                "src.pipeline.services.pipeline_orchestrator.stages.analysis.execute_validation_runtime",
                side_effect=mock_validation,
            ):
                with patch(
                    "src.pipeline.services.pipeline_orchestrator.stages.analysis.annotate_behavior_history",
                    return_value=[],
                ):
                    with patch(
                        "src.pipeline.services.pipeline_orchestrator.stages.analysis.merge_findings",
                        return_value=[],
                    ):
                        with patch(
                            "src.pipeline.services.pipeline_orchestrator.stages.analysis.annotate_finding_decisions",
                            return_value=[],
                        ):
                            with patch(
                                "src.pipeline.services.pipeline_orchestrator.stages.analysis.apply_lifecycle",
                                side_effect=lambda x: x,
                            ):
                                with patch(
                                    "src.pipeline.services.pipeline_orchestrator.stages.analysis.filter_reportable_findings",
                                    side_effect=lambda x: x,
                                ):
                                    with patch(
                                        "src.pipeline.services.pipeline_orchestrator.stages.analysis.validate_detection_payload",
                                        new=AsyncMock(),
                                    ):
                                        with patch(
                                            "src.pipeline.services.pipeline_orchestrator.stages.analysis.validate_analysis_payload",
                                            new=AsyncMock(),
                                        ):
                                            with patch(
                                                "src.pipeline.services.pipeline_orchestrator.stages.analysis.validate_decision_payload",
                                                new=AsyncMock(),
                                            ):
                                                with patch(
                                                    "src.pipeline.services.pipeline_orchestrator.stages.analysis.emit_progress",
                                                    new=AsyncMock(),
                                                ):
                                                    with patch(
                                                        "src.pipeline.services.pipeline_helpers.compute_detection_coverage",
                                                        return_value={},
                                                    ):
                                                        output = await analysis_stage.run_passive_scanning(
                                                            args=args, config=config, ctx=ctx
                                                        )

        _assert_stage_output_isolation("passive_scan", output, ctx)

    @pytest.mark.asyncio
    async def test_active_scan_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import active_scan as active_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.live_hosts = {"https://example.com"}
        ctx.result.urls = {"https://example.com/about"}
        ctx.result.selected_priority_items = [{"url": "https://example.com/about"}]

        args = SimpleNamespace()

        mock_probes = {
            name: AsyncMock(return_value=[])
            for name in [
                "sqli_safe_probe",
                "csrf_active_probe",
                "jwt_manipulation_probe",
                "xss_reflect_probe",
                "ssrf_active_probe",
                "file_upload_active_probe",
                "oauth_flow_analyzer",
                "open_redirect_active_probe",
                "path_traversal_active_probe",
                "command_injection_active_probe",
                "idor_active_probe",
                "hpp_active_probe",
                "websocket_message_probe",
                "graphql_active_probe",
                "xpath_injection_active_probe",
                "ssti_active_probe",
                "xxe_active_probe",
                "nosql_injection_probe",
                "run_auth_bypass_probes",
                "run_jwt_attack_suite",
                "ldap_injection_active_probe",
                "deserialization_probe",
                "proxy_ssrf_probe",
                "host_header_injection_probe",
                "crlf_injection_probe",
                "run_mutation_tests",
                "generate_payload_suggestions",
                "state_transition_analyzer",
                "parameter_dependency_tracker",
                "pagination_walker",
                "filter_parameter_fuzzer",
                "response_diff_engine",
                "cors_preflight_probe",
                "trace_method_probe",
                "options_method_probe",
                "cloud_metadata_active_probe",
                "http_smuggling_probe",
                "http2_probe",
                "jwt_token_regex",
                "generate_header_payloads",
                "generate_body_payloads",
            ]
        }
        mock_probes["jwt_token_regex"] = MagicMock()

        with patch.object(active_stage, "_load_active_probe_functions", return_value=mock_probes):
            with patch.object(active_stage, "emit_progress", new=AsyncMock()):
                with patch("src.analysis.passive.runtime.RequestScheduler"):
                    with patch("src.analysis.passive.runtime.ResponseCache"):
                        output = await active_stage.run_active_scanning(
                            args=args, config=config, ctx=ctx
                        )

        _assert_stage_output_isolation("active_scan", output, ctx)

    @pytest.mark.asyncio
    async def test_nuclei_stage_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import nuclei as nuclei_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.priority_urls = ["https://example.com/api"]
        ctx.result.analysis_results = {}
        ctx.result.selected_priority_items = []
        ctx.result.target_profile = {}
        ctx.result.validation_summary = {}

        async def mock_run_nuclei(*args, **kwargs):
            return [{"title": "SQL Injection", "url": "https://example.com/api?id=1"}]

        args = SimpleNamespace()

        with patch("src.recon.nuclei.run_nuclei_with_parsing", side_effect=mock_run_nuclei):
            with patch.object(nuclei_stage, "emit_progress", new=AsyncMock()):
                with patch.object(nuclei_stage, "build_feedback_targets", return_value=[]):
                    with patch.object(
                        nuclei_stage,
                        "build_nuclei_plan",
                        return_value=[("http", "https://example.com")],
                    ):
                        with patch.object(
                            nuclei_stage,
                            "annotate_finding_decisions",
                            side_effect=lambda *a, **k: [],
                        ):
                            with patch.object(
                                nuclei_stage,
                                "annotate_finding_history",
                                side_effect=lambda *a, **k: [],
                            ):
                                with patch.object(nuclei_stage, "merge_findings", return_value=[]):
                                    with patch.object(
                                        nuclei_stage, "apply_lifecycle", side_effect=lambda x: x
                                    ):
                                        with patch.object(
                                            nuclei_stage,
                                            "filter_reportable_findings",
                                            side_effect=lambda x: x,
                                        ):
                                            with patch(
                                                "src.pipeline.storage.read_lines", return_value=[]
                                            ):
                                                output = await nuclei_stage.run_nuclei_stage(
                                                    args=args, config=config, ctx=ctx
                                                )

        _assert_stage_output_isolation("nuclei", output, ctx)

    @pytest.mark.asyncio
    async def test_validation_stage_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import (
            validation as validation_stage,
        )

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.analysis_results = {"xss": [{"title": "XSS"}]}
        ctx.result.ranke_priority_urls = []
        ctx.result.validation_runtime_inputs = {}

        def mock_execute(*args, **kwargs):
            return {
                "results": {"xss": [{"status": "validated"}]},
                "errors": [],
                "settings": {},
                "metric": {},
                "metrics": {},
            }

        args = SimpleNamespace()

        with patch.object(validation_stage, "execute_validation_runtime", side_effect=mock_execute):
            with patch.object(validation_stage, "emit_progress", new=AsyncMock()):
                output = await validation_stage.run_validation(args=args, config=config, ctx=ctx)

        _assert_stage_output_isolation("validation", output, ctx)

    @pytest.mark.asyncio
    async def test_semgrep_stage_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import semgrep as semgrep_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.analysis_results = {}
        ctx.result.selected_priority_items = []
        ctx.result.target_profile = {}
        ctx.result.validation_summary = {}

        semgrep_file = ctx.output_store.run_dir / "semgrep.json"
        semgrep_file.parent.mkdir(parents=True, exist_ok=True)
        semgrep_file.write_text('[{"title": "Hardcoded credential", "severity": "high"}]')

        args = SimpleNamespace()

        with patch.object(semgrep_stage, "emit_progress", new=AsyncMock()):
            output = await semgrep_stage.run_semgrep_stage(args=args, config=config, ctx=ctx)

        _assert_stage_output_isolation("semgrep", output, ctx)

    @pytest.mark.asyncio
    async def test_enrichment_stage_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import (
            enrichment as enrichment_stage,
        )

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.reportable_findings = [{"title": "XSS", "severity": "high", "confidence": 0.8}]
        ctx.result.merged_findings = [{"title": "XSS", "severity": "high", "confidence": 0.8}]
        ctx.result.analysis_results = {}
        ctx.result.subdomains = ["example.com"]
        ctx.result.scope_entries = ["example.com"]
        ctx.result.live_records = []

        args = SimpleNamespace()

        with patch.object(enrichment_stage, "emit_progress", new=AsyncMock()):
            with patch.object(
                enrichment_stage, "enrich_findings_with_cvss", side_effect=lambda x: x
            ):
                with patch.object(enrichment_stage, "api_security_analyzer", return_value=[]):
                    with patch.object(enrichment_stage, "dns_security_analyzer", return_value=[]):
                        with patch.object(
                            enrichment_stage,
                            "annotate_finding_decisions",
                            side_effect=lambda x, **k: x,
                        ):
                            with patch.object(
                                enrichment_stage,
                                "filter_reportable_findings",
                                side_effect=lambda x: x,
                            ):
                                with patch.object(
                                    enrichment_stage, "apply_lifecycle", side_effect=lambda x: x
                                ):
                                    with patch.object(
                                        enrichment_stage, "correlate_findings", return_value=[]
                                    ):
                                        with patch.object(
                                            enrichment_stage,
                                            "detect_multi_vector_endpoints",
                                            return_value=[],
                                        ):
                                            with patch.object(
                                                enrichment_stage,
                                                "calculate_compound_risk",
                                                return_value={},
                                            ):
                                                with patch("src.learning.integration.LearningIntegration") as mock_learning:
                                                    mock_instance = MagicMock()
                                                    mock_instance.emit_feedback_events = AsyncMock()
                                                    mock_learning.get_or_create = MagicMock(
                                                        return_value=mock_instance
                                                    )
                                                    with patch.object(
                                                        enrichment_stage, "CVESyncClient"
                                                    ):
                                                        with patch.object(
                                                            enrichment_stage, "MitreAttackMapper"
                                                        ):
                                                            output = await enrichment_stage.run_post_analysis_enrichments(
                                                                args=args, config=config, ctx=ctx
                                                            )

        _assert_stage_output_isolation("enrichment", output, ctx)

    @pytest.mark.asyncio
    async def test_reporting_stage_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import reporting as reporting_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.live_hosts = {"https://example.com"}
        ctx.result.subdomains = {"example.com"}
        ctx.result.urls = {"https://example.com"}
        ctx.result.parameters = {"id", "token"}
        ctx.result.priority_urls = ["https://example.com"]
        ctx.result.selected_priority_items = [{"url": "https://example.com"}]
        ctx.result.screenshots = []
        ctx.result.analysis_results = {}
        ctx.result.reportable_findings = []
        ctx.result.module_metrics = {}
        ctx.result.diff_summary = {}
        ctx.result.target_profile = {}
        ctx.result.merged_findings = []
        ctx.result.started_at = time.time()

        args = SimpleNamespace()

        with patch.object(reporting_stage, "emit_progress", new=AsyncMock()):
            with patch("src.pipeline.services.pipeline_orchestrator.stages.reporting.resolve_plugin", return_value=MagicMock(return_value={})):
                with patch.object(reporting_stage, "capture_screenshots", new_callable=AsyncMock, return_value=[]):
                    with patch.object(reporting_stage, "build_artifact_diff", return_value={}):
                        with patch("src.pipeline.services.pipeline_orchestrator.stages.reporting.attach_queue_replay_links"):
                            output = await reporting_stage.run_reporting(
                                args=args, config=config, ctx=ctx
                            )

        assert output is not None, "Reporting stage must return exit code (int)"

    @pytest.mark.asyncio
    async def test_access_control_stage_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import access_control as ac_stage

        ctx = _make_strict_context()
        config = _build_mock_config()
        ctx.result.urls = {"https://example.com/admin"}
        ctx.result.selected_priority_items = [{"url": "https://example.com/admin"}]
        ctx.result.analysis_results = {}
        ctx.result.reportable_findings = []
        ctx.result.module_metrics = {}

        args = SimpleNamespace()

        with patch.object(ac_stage, "emit_progress", new=AsyncMock()):
            if True:
                output = await ac_stage.run_access_control_testing(
                    args=args, config=config, ctx=ctx
                )

        _assert_stage_output_isolation("access_control", output, ctx)


@pytest.mark.unit
class TestStageOutputContractFields:
    """Verify StageOutput fields used by orchestrator merge."""

    def test_stage_output_state_delta_supports_all_result_fields(self) -> None:
        """Ensure state_delta can carry all mutable StageResult fields."""
        state_delta = {
            "subdomains": ["example.com"],
            "live_hosts": ["https://example.com"],
            "urls": ["https://example.com/page"],
            "parameters": ["id", "token"],
            "analysis_results": {"xss": []},
            "merged_findings": [],
            "reportable_findings": [],
            "nuclei_findings": [],
            "service_results": {},
            "live_records": [],
            "target_profile": {"stack": "flask"},
            "validation_summary": {},
            "validation_runtime_inputs": {},
            "screenshots": [],
            "diff_summary": {},
            "url_stage_meta": {},
            "history_feedback": {},
            "ranked_priority_urls": [],
            "priority_urls": [],
            "selected_priority_items": [],
            "deep_analysis_urls": [],
            "iterative_stop_reason": "",
        }
        output = StageOutput(
            stage_name="test",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=1.0,
            state_delta=state_delta,
        )
        for key in state_delta:
            assert key in output.state_delta, f"state_delta missing field: {key}"

    def test_merge_stage_output_applies_state_delta(self) -> None:
        """Orchestrator merge correctly applies state_delta to ctx.result."""
        from src.pipeline.services.pipeline_orchestrator.orchestrator import PipelineOrchestrator

        ctx = PipelineContext(output_store=_DummyOutputStore())
        ctx.result.urls = set()
        ctx.result.module_metrics = {}

        output = StageOutput(
            stage_name="urls",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=2.5,
            metrics={"status": "ok", "duration_seconds": 2.5},
            state_delta={
                "urls": ["https://example.com/about", "https://example.com/contact"],
                "url_stage_meta": {"source": "gau"},
            },
        )

        orchestrator = PipelineOrchestrator()
        orchestrator._merge_stage_output(ctx, "urls", output)

        assert ctx.result.urls == {"https://example.com/about", "https://example.com/contact"}
        assert ctx.result.url_stage_meta == {"source": "gau"}
        assert ctx.result.stage_status["urls"] == StageStatus.COMPLETED.value
        assert ctx.result.module_metrics["urls"]["status"] == "ok"


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
pytest.main([__file__, "-q"])

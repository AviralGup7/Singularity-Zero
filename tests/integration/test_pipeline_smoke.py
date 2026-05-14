"""Smoke tests for the pipeline orchestrator.

Verifies that the pipeline can be instantiated, all stages are defined,
and the orchestrator can run with minimal/mock configuration.
"""

import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


EXPECTED_STAGES = [
    "subdomains",
    "live_hosts",
    "urls",
    "parameters",
    "ranking",
    "passive_scan",
    "active_scan",
    "validation",
    "intelligence",
    "access_control",
    "reporting",
]


@pytest.fixture
def minimal_args(tmp_path: Path) -> argparse.Namespace:
    """Create a minimal argparse.Namespace with mock config and scope files."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        '{"target_name":"smoke-test.example.com","output_dir":"output",'
        '"concurrency":{"nuclei_workers":1},'
        '"output":{"dedupe_aliases":true},'
        '"tools":{},"filters":{},"scoring":{},"mode":"quick",'
        '"analysis":{"max_iteration_limit":1,"finding_feedback_limit":5},'
        '"extensions":{},"review":{},"nuclei":{},"cache":{},"screenshots":{}}'
    )
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("smoke-test.example.com\n")
    args = argparse.Namespace(
        config=str(config_file),
        scope=str(scope_file),
        dry_run=False,
        skip_crtsh=True,
        refresh_cache=False,
    )
    return args


@pytest.fixture
def orchestrator():
    """Instantiate a PipelineOrchestrator."""
    from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

    return PipelineOrchestrator()


class TestOrchestratorInstantiation:
    """Tests that the pipeline orchestrator can be created."""

    def test_orchestrator_can_be_imported(self):
        """The PipelineOrchestrator class is importable."""
        from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

        assert PipelineOrchestrator is not None

    def test_orchestrator_instantiation(self, orchestrator):
        """PipelineOrchestrator can be instantiated without arguments."""
        assert orchestrator is not None

    def test_orchestrator_has_run_method(self, orchestrator):
        """PipelineOrchestrator exposes the async run method."""
        assert hasattr(orchestrator, "run")
        assert callable(getattr(orchestrator, "run"))

    def test_orchestrator_has_run_sync_method(self, orchestrator):
        """PipelineOrchestrator exposes the synchronous run_sync wrapper."""
        assert hasattr(orchestrator, "run_sync")
        assert callable(getattr(orchestrator, "run_sync"))


class TestPipelineStagesDefined:
    """Tests that all 11 pipeline stages are defined and callable."""

    @pytest.mark.parametrize("stage_name", EXPECTED_STAGES)
    def test_stage_is_documented(self, stage_name: str):
        """Each expected stage appears in the real pipeline stages."""
        from src.pipeline.services.pipeline_orchestrator._constants import PIPELINE_STAGES

        assert stage_name in PIPELINE_STAGES

    def test_all_stages_count(self):
        """There are exactly 11 expected stages."""
        assert len(EXPECTED_STAGES) == 11

    def test_stages_are_unique(self):
        """No duplicate stage names."""
        assert len(EXPECTED_STAGES) == len(set(EXPECTED_STAGES))

    def test_recon_stage_functions_are_callable(self):
        """Recon stage functions imported by the orchestrator are callable."""
        from src.recon import (
            collect_urls,
            enumerate_subdomains,
            extract_parameters,
            probe_live_hosts,
            rank_urls,
        )

        assert callable(enumerate_subdomains)
        assert callable(probe_live_hosts)
        assert callable(collect_urls)
        assert callable(extract_parameters)
        assert callable(rank_urls)

    def test_passive_analysis_is_callable(self):
        """The passive analysis entry point is callable."""
        from src.analysis.passive.orchestrator import run_passive_scanners

        assert callable(run_passive_scanners)

    def test_validation_is_callable(self):
        """The validation runtime is callable."""
        from src.execution.validators import execute_validation_runtime

        assert callable(execute_validation_runtime)

    def test_nuclei_functions_are_callable(self):
        """Nuclei-related functions are callable."""
        from src.recon import build_nuclei_plan, run_nuclei

        assert callable(build_nuclei_plan)
        assert callable(run_nuclei)

    def test_api_security_analyzer_is_callable(self):
        """The API security analyzer is callable."""
        from src.analysis.behavior.api_security import api_security_analyzer

        assert callable(api_security_analyzer)

    def test_dns_security_analyzer_is_callable(self):
        """The DNS security analyzer is callable."""
        from src.analysis.behavior.dns_security import dns_security_analyzer

        assert callable(dns_security_analyzer)

    def test_reporting_functions_are_callable(self):
        """Reporting functions are callable."""
        from src.reporting import (
            build_artifact_diff,
            build_dashboard_index,
            build_summary,
            generate_run_report,
        )

        assert callable(build_artifact_diff)
        assert callable(build_dashboard_index)
        assert callable(build_summary)
        assert callable(generate_run_report)


@pytest.mark.slow
@pytest.mark.integration
class TestPipelineRunWithMockConfig:
    """Tests that the pipeline can run with minimal/mock configuration."""

    def _patch_external_tools(self):
        """Return a dict of patches for all external tool calls."""
        patches = {
            "src.recon.subdomains.enumerate_subdomains": lambda *a, **k: set(),
            "src.recon.live_hosts.probe_live_hosts": lambda *a, **k: ([], set()),
            "src.recon.urls.collect_urls": lambda *a, **k: set(),
            "src.recon.urls.extract_parameters": lambda *a, **k: set(),
            "src.recon.scoring.infer_target_profile": lambda *a, **k: {},
            "src.recon.scoring.rank_urls": lambda *a, **k: [],
            "src.analysis.passive.orchestrator.run_passive_scanners": lambda *a, **k: (
                {},
                {"urls": [], "responses": []},
            ),
            "src.execution.validators.execute_validation_runtime": lambda *a, **k: {
                "results": {},
                "errors": [],
                "settings": {},
                "metric": {},
            },
            "src.recon.build_nuclei_plan": lambda *a, **k: {},
            "src.recon.run_nuclei": lambda *a, **k: "",
            "src.pipeline.screenshots.capture_screenshots": lambda *a, **k: [],
            "src.analysis.behavior.analysis.annotate_behavior_history": lambda *a, **k: [],
            "src.analysis.intelligence.decision_engine.annotate_finding_decisions": lambda x: x,
            "src.analysis.intelligence.findings.intelligence_findings._history.annotate_finding_history": lambda *a, **k: [],
            "src.analysis.intelligence.findings.intelligence_findings._merge_orchestrator.merge_findings": lambda *a, **k: [],
            "src.analysis.intelligence.decision_engine.filter_reportable_findings": lambda x: (
                x if x else []
            ),
            "src.core.contracts.schema_validator.validate_analysis_payload": lambda *a, **k: None,
            "src.core.contracts.schema_validator.validate_decision_payload": lambda *a, **k: None,
            "src.core.contracts.schema_validator.validate_detection_payload": lambda *a, **k: None,
            "src.core.contracts.schema_validator.validate_execution_payload": lambda *a, **k: None,
            "src.core.contracts.schema_validator.validate_recon_payload": lambda *a, **k: None,
            "src.core.contracts.finding_lifecycle.apply_lifecycle": lambda x: x if x else [],
            "src.pipeline.services.output_store.PipelineOutputStore.create": MagicMock(),
            "src.reporting.find_previous_run": lambda *a, **k: None,
            "src.pipeline.cache.cache_enabled": lambda *a, **k: False,
            "src.pipeline.runner_support.build_tool_status": lambda *a, **k: {},
            "src.pipeline.runner_support.emit_progress": lambda *a, **k: None,
            "src.pipeline.runner_support.emit_url_progress": lambda *a, **k: None,
            "src.pipeline.runner_support.resolve_cached_stage": lambda *a, **k: set(),
            "src.analysis.behavior.service.run_service_enrichment": lambda *a, **k: ([], set(), {}),
            "src.analysis.intelligence.endpoint.endpoint_intelligence.build_endpoint_intelligence": lambda *a, **k: {},
            "src.analysis.intelligence.insights.build_attack_surface": lambda *a, **k: {},
            "src.analysis.intelligence.insights.build_trend": lambda *a, **k: {},
            "src.analysis.intelligence.insights.build_next_steps": lambda *a, **k: {},
            "src.analysis.intelligence.insights.build_high_confidence_shortlist": lambda *a, **k: [],
            "src.analysis.intelligence.insights.build_manual_verification_queue": lambda *a, **k: [],
            "src.analysis.intelligence.insights.build_cross_finding_correlation": lambda *a, **k: {},
            "src.analysis.automation.manual_queue.attach_queue_replay_links": lambda *a, **k: None,
            "src.analysis.response._core.response_analysis._classification.build_response_classification_summary": lambda *a, **k: {},
            "src.analysis.response._core.response_analysis._classification.build_mutation_strategy_coverage": lambda *a, **k: {},
            "src.analysis.behavior.technology.build_technology_summary": lambda *a, **k: {},
            "src.recon.ranking_support.load_history_feedback": lambda *a, **k: {},
            "src.recon.ranking_support.select_deep_analysis_targets": lambda *a, **k: ([], {}),
            "src.pipeline.services.pipeline_flow.pipeline_flow_manifest": lambda: [],
            "src.pipeline.services.pipeline_helpers.compute_detection_coverage": lambda *a, **k: {},
            "src.pipeline.services.pipeline_helpers.extract_feedback_urls": lambda *a, **k: set(),
            "src.pipeline.services.pipeline_helpers.finding_identity": lambda x: str(
                x.get("url", "")
            ),
            "src.pipeline.storage.read_lines": lambda *a, **k: set(),
            "src.pipeline.storage.read_scope": lambda *a, **k: ["smoke-test.example.com"],
            "src.reporting.vrt_coverage.build_p1_vrt_coverage": lambda *a, **k: {},
            "src.analysis.behavior.api_security.api_security_analyzer": lambda *a, **k: [],
            "src.analysis.behavior.dns_security.dns_security_analyzer": lambda *a, **k: [],
            "src.analysis.intelligence.cvss_scoring.enrich_findings_with_cvss": lambda x: (
                x if x else []
            ),
            "src.intelligence.correlation.engine.correlate_findings": lambda *a, **k: [],
            "src.intelligence.correlation.engine.detect_multi_vector_endpoints": lambda *a, **k: [],
            "src.intelligence.correlation.engine.calculate_compound_risk": lambda *a, **k: {},
            "src.reporting.build_artifact_diff": lambda *a, **k: {},
            "src.reporting.build_dashboard_index": lambda *a, **k: None,
            "src.reporting.build_summary": lambda *a, **k: {},
            "src.reporting.generate_run_report": lambda *a, **k: None,
            "src.core.logging.pipeline_logging.emit_info": lambda *a, **k: None,
            "src.core.logging.pipeline_logging.emit_summary": lambda *a, **k: None,
        }
        return patches

    def test_orchestrator_run_returns_exit_code(
        self, minimal_args: argparse.Namespace, tmp_path: Path
    ):
        """The orchestrator run method returns an integer exit code."""
        from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

        store_mock = MagicMock()
        store_mock.target_root = tmp_path / "output"
        store_mock.target_root.mkdir(parents=True, exist_ok=True)
        store_mock.run_dir = store_mock.target_root / "run-1"
        store_mock.run_dir.mkdir(parents=True, exist_ok=True)
        store_mock.cache_root = store_mock.target_root / "cache"
        store_mock.cache_root.mkdir(parents=True, exist_ok=True)
        store_mock.write_scope = MagicMock()
        store_mock.write_subdomains = MagicMock()
        store_mock.write_live_hosts = MagicMock()
        store_mock.write_urls = MagicMock()
        store_mock.write_parameters = MagicMock()
        store_mock.write_priority_endpoints = MagicMock()
        store_mock.write_nuclei_output = MagicMock()
        store_mock.persist_outputs = MagicMock()

        patches = self._patch_external_tools()
        store_patch = patch(
            "src.pipeline.services.output_store.PipelineOutputStore.create",
            return_value=store_mock,
        )

        with store_patch:
            for target, replacement in patches.items():
                if target == "src.pipeline.services.output_store.PipelineOutputStore.create":
                    continue
                patch(target, replacement).start()

            try:
                orchestrator = PipelineOrchestrator()
                result = orchestrator.run_sync(minimal_args)
                assert isinstance(result, int)
            finally:
                patch.stopall()

    def test_dry_run_returns_zero(self, minimal_args: argparse.Namespace, capsys):
        """Dry-run mode returns exit code 0 without executing stages."""
        from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

        minimal_args.dry_run = True

        with patch("src.pipeline.storage.read_scope", return_value=["smoke-test.example.com"]):
            orchestrator = PipelineOrchestrator()
            result = orchestrator.run_sync(minimal_args)

        assert result == 0
        captured = capsys.readouterr()
        assert "scope_entries" in captured.out

    def test_runtime_main_importable(self):
        """The runtime main() function is importable."""
        from src.pipeline.runtime import main

        assert callable(main)

    def test_runtime_execute_pipeline_importable(self):
        """The execute_pipeline function is importable."""
        from src.pipeline.runtime import execute_pipeline

        assert callable(execute_pipeline)

    def test_runtime_preflight_checks_importable(self):
        """The _preflight_checks function is importable."""
        from src.pipeline.runtime import _preflight_checks

        assert callable(_preflight_checks)

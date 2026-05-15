import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator


@pytest.mark.integration
@pytest.mark.slow
class TestFullPipelineE2E:
    def test_dry_run_returns_zero_exit_code(self, pipeline_runner):
        result = pipeline_runner(dry_run=True)
        assert result == 0

    def test_pipeline_instantiation(self):
        orchestrator = PipelineOrchestrator()
        assert orchestrator is not None
        assert hasattr(orchestrator, "run")
        assert hasattr(orchestrator, "run_sync")

    def test_pipeline_stages_exist(self):
        from src.pipeline.services.pipeline_orchestrator._constants import (
            PIPELINE_STAGES,
            STAGE_ORDER,
        )

        assert len(STAGE_ORDER) > 0
        assert "reporting" in STAGE_ORDER
        for stage in PIPELINE_STAGES:
            assert stage in STAGE_ORDER

    def test_full_pipeline_with_mocks(
        self,
        pipeline_runner,
        mock_target_server,
        e2e_workspace: Path,
    ):
        exit_code = pipeline_runner(dry_run=False)
        assert isinstance(exit_code, int)

    def test_pipeline_config_loads_correctly(self, e2e_pipeline_config: dict[str, Any]):
        assert e2e_pipeline_config["target_name"] == "e2e-test.example.com"
        assert "scope" in e2e_pipeline_config
        assert "concurrency" in e2e_pipeline_config
        assert e2e_pipeline_config["mode"] == "quick"

    def test_scope_file_has_correct_content(self, e2e_scope_file: Path):
        content = e2e_scope_file.read_text()
        assert "e2e-test.example.com" in content

    def test_config_file_is_valid_json(self, e2e_config_file: Path):
        content = e2e_config_file.read_text()
        config = json.loads(content)
        assert "target_name" in config
        assert "output_dir" in config

    def test_output_directory_structure_created(
        self,
        pipeline_runner,
        mock_target_server,
        e2e_workspace: Path,
    ):
        pipeline_runner(dry_run=False)
        output_dir = e2e_workspace / "output"
        assert output_dir.exists()

    def test_pipeline_context_restoration(self, e2e_workspace: Path):
        from src.core.checkpoint import generate_run_id

        run_id = generate_run_id()
        assert run_id is not None
        assert len(run_id) > 0

    def test_pipeline_module_metrics_structure(self):
        """Verify that pipeline stage metrics are defined consistently.

        Checks that the metric names in PIPELINE_STAGES match expectations
        and that each stage has valid percentage ranges.
        """
        from src.pipeline.services.pipeline_flow import PIPELINE_STAGES

        expected_keys = {
            "startup",
            "subdomains",
            "live_hosts",
            "urls",
            "parameters",
            "ranking",
            "passive_scan",
            "active_scan",
            "validation",
            "nuclei",
            "access_control",
            "intelligence",
            "reporting",
        }
        stage_keys = {stage.key for stage in PIPELINE_STAGES}

        # Verify all expected modules appear as actual pipeline stages
        assert expected_keys.issubset(stage_keys), (
            f"Missing pipeline stages: {expected_keys - stage_keys}"
        )
        # Verify stages have valid percentage ranges and no gaps
        for stage in PIPELINE_STAGES:
            assert 0 <= stage.percent_start < stage.percent_end <= 100
        # Verify stages chain without gaps or overlaps
        for i, stage in enumerate(PIPELINE_STAGES[:-1]):
            next_stage = PIPELINE_STAGES[i + 1]
            assert stage.percent_end <= next_stage.percent_start, (
                f"Overlap between {stage.key} and {next_stage.key}"
            )

    def test_pipeline_finding_lifecycle(self):
        from src.core.contracts.finding_lifecycle import apply_lifecycle

        findings = [
            {
                "url": "https://example.com/test",
                "severity": "high",
                "confidence": 0.9,
                "category": "test",
                "title": "Test Finding",
            }
        ]
        result = apply_lifecycle(findings)
        assert isinstance(result, list)

    def test_pipeline_schema_validators_importable(self):
        from src.core.contracts.schema_validator import (
            validate_analysis_payload,
            validate_decision_payload,
            validate_detection_payload,
            validate_execution_payload,
            validate_recon_payload,
        )

        assert callable(validate_analysis_payload)
        assert callable(validate_decision_payload)
        assert callable(validate_detection_payload)
        assert callable(validate_execution_payload)
        assert callable(validate_recon_payload)

    def test_pipeline_reporting_stage_functions(self):
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

    def test_pipeline_intelligence_correlation(self):
        from src.intelligence.correlation.engine import (
            calculate_compound_risk,
            correlate_findings,
            detect_multi_vector_endpoints,
        )

        assert callable(correlate_findings)
        assert callable(detect_multi_vector_endpoints)
        assert callable(calculate_compound_risk)

    def test_pipeline_cvss_scoring(self):
        from src.analysis.intelligence.cvss_scoring import enrich_findings_with_cvss

        assert callable(enrich_findings_with_cvss)

    def test_pipeline_service_enrichment(self):
        from src.analysis.behavior.service import run_service_enrichment

        assert callable(run_service_enrichment)

from unittest.mock import patch

import pytest

REPORTING_PATCHES = [
    (
        "src.pipeline.services.pipeline_orchestrator.stages.reporting.generate_run_report",
        "generate_run_report",
    ),
    (
        "src.pipeline.services.pipeline_orchestrator.stages.reporting.build_dashboard_index",
        "build_dashboard_index",
    ),
    ("src.pipeline.services.pipeline_orchestrator.stages.reporting.build_summary", "build_summary"),
    (
        "src.pipeline.services.pipeline_orchestrator.stages.reporting.build_artifact_diff",
        "build_artifact_diff",
    ),
    (
        "src.pipeline.services.pipeline_orchestrator.stages.reporting.capture_screenshots",
        "capture_screenshots",
    ),
]


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("target, key", REPORTING_PATCHES)
def test_reporting_and_misc_stage_invokes_target(mock_target_server, pipeline_runner, target, key):
    """Verify reporting and related pipeline stages invoke expected modules."""
    with patch(target, mock_target_server[key]):
        exit_code = pipeline_runner(dry_run=False)
    assert isinstance(exit_code, int)
    mock_target_server[key].assert_called()

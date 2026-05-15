from unittest.mock import patch

import pytest

ANALYSIS_PATCHES = [
    (
        "src.pipeline.services.pipeline_orchestrator.stages.analysis.run_passive_scanners",
        "run_passive_scanners",
    ),
    (
        "src.pipeline.services.pipeline_orchestrator.stages.analysis.execute_validation_runtime",
        "execute_validation_runtime",
    ),
    (
        "src.pipeline.services.pipeline_orchestrator.stages.analysis.merge_findings",
        "merge_findings",
    ),
    (
        "src.pipeline.services.pipeline_orchestrator.stages.analysis.filter_reportable_findings",
        "filter_reportable_findings",
    ),
]


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("target, key", ANALYSIS_PATCHES)
def test_analysis_stage_invokes_target(mock_target_server, pipeline_runner, target, key):
    """Each analysis-related stage should be invoked when patched."""
    with patch(target, mock_target_server[key]):
        exit_code = pipeline_runner(dry_run=False)
    assert isinstance(exit_code, int)
    mock_target_server[key].assert_called()

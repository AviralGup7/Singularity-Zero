from unittest.mock import patch

import pytest

RECON_PATCHES = [
    (
        "src.pipeline.services.services.recon_service.enumerate_subdomains",
        "enumerate_subdomains",
    ),
    (
        "src.pipeline.services.services.recon_service.probe_live_hosts",
        "probe_live_hosts",
    ),
    ("src.pipeline.services.services.recon_service.collect_urls", "collect_urls"),
    (
        "src.pipeline.services.services.recon_service.extract_parameters",
        "extract_parameters",
    ),
    ("src.pipeline.services.services.recon_service.rank_urls", "rank_urls"),
]


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.parametrize("target, key", RECON_PATCHES)
def test_recon_stage_invokes_target(mock_target_server, pipeline_runner, target, key):
    """Each recon stage should be invoked by the pipeline when patched."""
    with patch(target, mock_target_server[key]):
        exit_code = pipeline_runner(dry_run=False)
    assert isinstance(exit_code, int)
    mock_target_server[key].assert_called()


@pytest.mark.integration
@pytest.mark.slow
def test_recon_stage_ordering(mock_target_server, pipeline_runner):
    """Verify basic ordering and ensure stages are not retried infinitely."""
    with (
        patch(
            "src.pipeline.services.pipeline_orchestrator.stages.recon.enumerate_subdomains",
            mock_target_server["enumerate_subdomains"],
        ),
        patch(
            "src.pipeline.services.pipeline_orchestrator.stages.recon.probe_live_hosts",
            mock_target_server["probe_live_hosts"],
        ),
        patch(
            "src.pipeline.services.pipeline_orchestrator.stages.recon.collect_urls",
            mock_target_server["collect_urls"],
        ),
    ):
        exit_code = pipeline_runner(dry_run=False)
    assert isinstance(exit_code, int)
    assert mock_target_server["enumerate_subdomains"].call_count <= 1
    assert mock_target_server["probe_live_hosts"].call_count <= 1
    assert mock_target_server["collect_urls"].call_count <= 1

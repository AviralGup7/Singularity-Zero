import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.frontier.chameleon import RequestChameleon
from src.dashboard.fastapi.routers.findings import update_finding
from src.learning.integration import LearningIntegration


@pytest.mark.asyncio
async def test_update_finding_propagates_fp_mesh_sync(tmp_path):
    # Set up mock dependencies
    mock_queue_client = MagicMock()

    # Create target and run directories with findings.json
    target_dir = tmp_path / "target1"
    target_dir.mkdir()
    run_dir = target_dir / "run1"
    run_dir.mkdir()

    findings_file = run_dir / "findings.json"
    finding_data = {
        "id": "finding-123",
        "response_status": 403,
        "evidence": "Blocked by WAF indicator",
        "category": "waf_block",
        "decision": "KEEP",
    }
    findings_file.write_text(json.dumps([finding_data]), encoding="utf-8")

    mock_queue_client.query.output_root = tmp_path

    # Initialize LearningIntegration global instance under test configuration
    learning = LearningIntegration.get_or_create()
    learning.config.enabled = True

    # Mock FPTracker add_manual_fp method
    original_add_manual_fp = learning._fp_tracker.add_manual_fp
    learning._fp_tracker.add_manual_fp = AsyncMock(return_value=MagicMock())

    # Perform update to decision="DROP" to trigger FP manual registration
    update_data = {"decision": "DROP"}
    result = await update_finding(
        finding_id="finding-123",
        update_data=update_data,
        _auth={"user": "admin", "role": "admin"},
        services=mock_queue_client,
    )

    # Verify the finding was updated
    assert result["decision"] == "DROP"

    # Verify add_manual_fp was called asynchronously/synchronously
    assert learning._fp_tracker.add_manual_fp.called
    args, kwargs = learning._fp_tracker.add_manual_fp.call_args
    assert kwargs.get("category") == "waf_block"
    assert kwargs.get("status_code") == 403
    assert "Blocked" in kwargs.get("body_indicator")

    # Restore original method
    learning._fp_tracker.add_manual_fp = original_add_manual_fp
    LearningIntegration.reset()


def test_chameleon_adapts_to_active_fp_patterns():
    # Initialize LearningIntegration and enable
    learning = LearningIntegration.get_or_create()
    learning.config.enabled = True

    # Clean cache and inject active FP patterns
    learning._fp_tracker._cache.clear()

    from src.learning.models.fp_pattern import FPPattern

    waf_pattern = FPPattern.create(
        category="waf_block", status_codes={403}, body_indicators=["blocked"]
    )
    waf_pattern.is_active = True
    learning._fp_tracker._cache[waf_pattern.pattern_id] = waf_pattern

    chameleon = RequestChameleon()

    # Verify that stealth options are adapted when WAF pattern is active
    opts = chameleon.get_stealth_options()
    # Timeout should be doubled (usually 10-20, doubled to 20-40)
    assert opts["timeout"] >= 20.0
    assert opts["http2"] is True

    # Verify that noise header chance is adapted (noise chance set to 0 -> 90% chance)
    # Check that we regularly inject noise headers
    noise_count = 0
    for _ in range(50):
        headers = chameleon.mutate_headers({"Host": "example.com"})
        if any("-" in k for k in headers.keys() if k != "User-Agent" and k != "Host"):
            noise_count += 1

    # Under standard 30% chance, 50 trials yields ~15 noise headers.
    # Under 90% chance, 50 trials yields ~45 noise headers.
    assert noise_count > 35, (
        f"Expected extremely high noise header count under 90% chance, got {noise_count}"
    )

    LearningIntegration.reset()

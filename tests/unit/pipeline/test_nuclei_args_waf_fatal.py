"""Coverage for nuclei WAF args, WAF profiles, and fatal-metric detection."""

from __future__ import annotations

import pytest

from src.pipeline.nuclei_args_injector import build_nuclei_args
from src.pipeline.services.pipeline_orchestrator._orchestrator.fatal_detection import (
    metrics_indicate_fatal_failure,
)
from src.pipeline.waf_profile import WAFProfile, WAFTuningProfile


@pytest.mark.unit
def test_build_nuclei_args_injects_missing_flags() -> None:
    args = build_nuclei_args(["-u", "https://example.com"], waf_profile=WAFProfile.NONE)
    assert args[:2] == ["-u", "https://example.com"]
    assert args[args.index("-rl") + 1] == "150"
    assert args[args.index("-timeout") + 1] == "5"
    assert args[args.index("-retries") + 1] == "2"


@pytest.mark.unit
def test_build_nuclei_args_does_not_duplicate_existing_flags() -> None:
    existing = ["-rl", "7", "-timeout=9", "-retries", "0"]
    args = build_nuclei_args(existing, waf_profile=WAFProfile.CLOUDFLARE)
    assert args.count("-rl") == 1
    assert args[args.index("-rl") + 1] == "7"
    assert any(item.startswith("-timeout") for item in args)
    assert args.count("-retries") == 1
    assert existing == ["-rl", "7", "-timeout=9", "-retries", "0"]


@pytest.mark.unit
def test_waf_tuning_profiles_and_unknown_fallback() -> None:
    cf = WAFTuningProfile.for_profile("cloudflare")
    assert cf.nuclei_rate_limit == 10
    assert cf.to_circuit_breaker_config()["circuit_breaker_failure_threshold"] == 3
    generic = WAFTuningProfile.for_profile(WAFProfile.GENERIC)
    assert generic.httpx_concurrency == 40
    fallback = WAFTuningProfile.for_profile(WAFProfile.NONE)
    assert fallback.nuclei_rate_limit == 150


@pytest.mark.unit
@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        ({"status": "ok", "fatal": True}, False),
        ({"status": "success"}, False),
        ({"status": "completed"}, False),
        ({"status": "failed"}, True),
        ({"status": "error"}, True),
        ({"status": "timeout"}, True),
        ({"status": "failed", "fatal": False}, False),
        ({"status": "running", "fatal": "yes"}, True),
        ({"status": "running", "fatal": "false"}, False),
        ({"status": "running", "fatal": 1}, True),
        ("not-a-dict", False),
        ({}, False),
    ],
)
def test_metrics_indicate_fatal_failure(metrics: object, expected: bool) -> None:
    assert metrics_indicate_fatal_failure(metrics) is expected

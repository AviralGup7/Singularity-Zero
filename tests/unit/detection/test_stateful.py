import asyncio

import pytest

from src.detection.stateful import (
    adapt_rate_limit_observations,
    analyze_csrf_entropy,
    csrf_findings_from_observations,
    detect_session_fixation,
    fire_concurrent_requests,
    fixation_findings_from_observations,
    normalized_entropy,
    shannon_entropy,
)


def test_shannon_entropy_empty_returns_zero():
    assert shannon_entropy([]) == 0.0


def test_shannon_entropy_uniform_distribution():
    samples = ["abcd" * 16]
    assert shannon_entropy(samples) == pytest.approx(2.0, abs=0.01)


def test_shannon_entropy_single_char():
    assert shannon_entropy(["aaaa"]) == 0.0


def test_shannon_entropy_distinct_values_increase_entropy():
    e1 = shannon_entropy(["abcabc"])
    e2 = shannon_entropy(["abcdef"])
    assert e2 > e1


def test_normalized_entropy_in_unit_range():
    assert 0.0 <= normalized_entropy(["a" * 100]) <= 1.0
    assert 0.0 <= normalized_entropy(["abc", "xyz"]) <= 1.0
    assert 0.0 <= normalized_entropy([]) <= 1.0


def test_normalized_entropy_distinct_chars_higher_than_repeats():
    repeats = normalized_entropy(["x" * 50])
    varied = normalized_entropy(["abcdefghijklmnop"])
    assert varied > repeats


def test_analyze_csrf_entropy_static_tokens_flagged():
    finding = analyze_csrf_entropy(url="https://e", tokens=["abc", "abc", "abc", "abc"])
    assert finding.is_static is True
    assert finding.is_predictable is True
    assert finding.is_session_bound is True
    assert finding.sample_count == 4
    payload = finding.to_dict()
    assert payload["indicator"] == "csrf_entropy_weakness"
    assert payload["severity"] == "high"
    assert "csrf" in payload["indicator"]


def test_analyze_csrf_entropy_unique_tokens():
    samples = [f"tok{i:04d}{i*7:04d}" for i in range(10)]
    finding = analyze_csrf_entropy(url="https://e", tokens=samples)
    assert finding.is_static is False
    assert finding.unique_token_ratio == pytest.approx(1.0)
    payload = finding.to_dict()
    assert payload["severity"] in {"medium", "high"}


def test_analyze_csrf_entropy_empty_tokens():
    finding = analyze_csrf_entropy(url="https://e", tokens=[])
    assert finding.sample_count == 0
    assert finding.is_static is False


def test_analyze_csrf_entropy_field_passthrough():
    finding = analyze_csrf_entropy(
        url="https://e", tokens=["a", "b"], field="custom_field"
    )
    assert finding.field == "custom_field"
    assert finding.to_dict()["field"] == "custom_field"


def test_detect_session_fixation_vulnerable():
    finding = detect_session_fixation(
        url="https://e/login", pre_auth_token="ABC123", post_auth_token="ABC123"
    )
    assert finding.is_fixation is True
    assert finding.rotated_after_auth is False
    assert finding.token_length == 6
    payload = finding.to_dict()
    assert payload["indicator"] == "session_fixation_candidate"
    assert payload["severity"] == "high"


def test_detect_session_fixation_safe():
    finding = detect_session_fixation(
        url="https://e/login", pre_auth_token="PRE123", post_auth_token="POST456"
    )
    assert finding.is_fixation is False
    assert finding.rotated_after_auth is True
    payload = finding.to_dict()
    assert payload["severity"] == "info"


def test_detect_session_fixation_missing_token_returns_safe():
    finding = detect_session_fixation(
        url="https://e", pre_auth_token=None, post_auth_token="x"
    )
    assert finding.is_fixation is False


def test_detect_session_fixation_both_missing():
    finding = detect_session_fixation(
        url="https://e", pre_auth_token="", post_auth_token=""
    )
    assert finding.is_fixation is False
    assert finding.token_length == 0


def test_csrf_findings_from_observations():
    observations = [
        {"url": "https://e/a", "tokens": ["x", "x", "x"]},
        {"url": "https://e/b", "tokens": ["unique1", "unique2"]},
        {"url": "", "tokens": ["x"]},
        {"url": "https://e/c", "tokens": []},
    ]
    findings = csrf_findings_from_observations(observations)
    assert len(findings) == 2
    assert findings[0]["url"] == "https://e/a"
    assert findings[1]["url"] == "https://e/b"


def test_fixation_findings_from_observations():
    observations = [
        {"url": "https://e", "pre_auth_token": "PRE", "post_auth_token": "PRE"},
        {"url": "https://e2", "pre_auth_token": "PRE2", "post_auth_token": "POST2"},
        {"url": "", "pre_auth_token": "x", "post_auth_token": "x"},
    ]
    findings = fixation_findings_from_observations(observations)
    assert len(findings) == 2
    assert findings[0]["url"] == "https://e"
    assert findings[1]["url"] == "https://e2"


def test_adapt_rate_limit_observations_empty():
    result = adapt_rate_limit_observations(url="https://e", samples=[])
    assert result.throttled_status is None
    assert result.threshold_estimate is None
    assert result.samples == []


def test_adapt_rate_limit_observations_threshold_found():
    samples = [
        {"interval_ms": 50, "status_code": 200},
        {"interval_ms": 100, "status_code": 200},
        {"interval_ms": 500, "status_code": 200},
        {"interval_ms": 1000, "status_code": 429},
        {"interval_ms": 1500, "status_code": 200},
    ]
    result = adapt_rate_limit_observations(url="https://e", samples=samples)
    assert result.throttled_status == 429
    assert result.threshold_estimate == 1000
    assert result.baseline_status == 200
    assert result.last_status == 200


def test_adapt_rate_limit_observations_no_throttle():
    samples = [
        {"interval_ms": 50, "status_code": 200},
        {"interval_ms": 500, "status_code": 200},
        {"interval_ms": 1000, "status_code": 200},
    ]
    result = adapt_rate_limit_observations(url="https://e", samples=samples)
    assert result.throttled_status is None
    assert result.threshold_estimate is None


def test_adapt_rate_limit_observations_custom_status_codes():
    samples = [
        {"interval_ms": 50, "status_code": 200},
        {"interval_ms": 200, "status_code": 503},
    ]
    result = adapt_rate_limit_observations(
        url="https://e", samples=samples, threshold_status_codes=(503,)
    )
    assert result.throttled_status == 503
    assert result.threshold_estimate == 200


def test_adapt_rate_limit_to_dict():
    samples = [{"interval_ms": 100, "status_code": 200}, {"interval_ms": 200, "status_code": 429}]
    result = adapt_rate_limit_observations(url="https://e", samples=samples)
    payload = result.to_dict()
    assert payload["indicator"] == "rate_limit_adaptive_probe"
    assert "summary" in payload
    assert payload["threshold_estimate"] == 200


def test_fire_concurrent_requests_all_success():
    async def factory():
        class FakeResp:
            status_code = 200

        return FakeResp()

    result = asyncio.run(
        fire_concurrent_requests(factory, url="https://e", concurrency=4)
    )
    assert result.fired_concurrent == 4
    assert result.success_count == 4
    assert result.failure_count == 0
    assert result.drift_observed is False


def test_fire_concurrent_requests_drift_detected():
    async def factory():
        class FakeResp:
            status_code = 201

        return FakeResp()

    async def mixed_factory():
        class FakeResp:
            status_code = 500

        return FakeResp()

    counter = {"ok": 0}

    def rotating_factory():
        counter["ok"] += 1
        if counter["ok"] % 2:
            return factory()
        return mixed_factory()

    result = asyncio.run(
        fire_concurrent_requests(rotating_factory, url="https://e", concurrency=4)
    )
    assert result.fired_concurrent == 4
    assert result.success_count == 2
    assert result.failure_count == 2
    assert result.drift_observed is True


def test_fire_concurrent_requests_handles_exceptions():
    async def factory():
        raise RuntimeError("boom")

    result = asyncio.run(
        fire_concurrent_requests(factory, url="https://e", concurrency=3)
    )
    assert result.fired_concurrent == 3
    assert result.success_count == 0
    assert result.failure_count == 3
    assert result.drift_observed is False


def test_fire_concurrent_requests_to_dict_shape():
    async def factory():
        class FakeResp:
            status_code = 200

        return FakeResp()

    result = asyncio.run(
        fire_concurrent_requests(factory, url="https://e", concurrency=2)
    )
    payload = result.to_dict()
    assert payload["indicator"] == "race_condition_concurrent_probe"
    assert payload["fired_concurrent"] == 2
    assert payload["drift_observed"] is False
    assert "elapsed_ms" in payload

"""Tests for the API rate-limit differential analyzer."""

from src.detection.api.rate_limit_diff import (
    RateLimitEndpointObservation,
    build_endpoint_profiles,
    endpoint_profiles_to_findings,
)


def _obs(url: str, **overrides) -> RateLimitEndpointObservation:
    defaults = dict(
        url=url,
        method="POST",
        status_code=200,
        rate_limit_limit=60,
        rate_limit_remaining=59,
        rate_limit_reset=60,
        retry_after=None,
        throttled=False,
        request_count=1,
    )
    defaults.update(overrides)
    return RateLimitEndpointObservation(**defaults)


def test_sensitive_endpoint_with_no_limit_is_high() -> None:
    observations = [
        _obs("https://api.example.com/login", rate_limit_limit=None, rate_limit_remaining=None),
        _obs("https://api.example.com/login", rate_limit_limit=None, rate_limit_remaining=None),
        _obs(
            "https://api.example.com/api/orders",
            rate_limit_limit=120,
            rate_limit_remaining=119,
        ),
    ]
    profiles = build_endpoint_profiles(observations)
    findings = endpoint_profiles_to_findings(profiles)
    sensitive = [f for f in findings if f["endpoint_key"].endswith("/login")]
    assert sensitive, findings
    assert sensitive[0]["indicator"] == "api_rate_limit_missing_sensitive"
    assert sensitive[0]["severity"] == "high"


def test_weakest_link_is_reported() -> None:
    observations = [
        _obs("https://api.example.com/api/list", rate_limit_limit=200, rate_limit_remaining=199),
        _obs("https://api.example.com/api/reports", rate_limit_limit=5, rate_limit_remaining=4),
    ]
    profiles = build_endpoint_profiles(observations)
    findings = endpoint_profiles_to_findings(profiles)
    weakest = [f for f in findings if f["weakest_link"]]
    assert weakest
    assert weakest[0]["endpoint_key"].endswith("/api/reports")


def test_inconsistent_limit_header_is_flagged() -> None:
    observations = [
        _obs("https://api.example.com/api/items", rate_limit_limit=100, rate_limit_remaining=99),
        _obs("https://api.example.com/api/items", rate_limit_limit=80, rate_limit_remaining=79),
    ]
    profiles = build_endpoint_profiles(observations)
    findings = endpoint_profiles_to_findings(profiles)
    item_findings = [f for f in findings if f["endpoint_key"].endswith("/api/items")]
    assert item_findings
    assert "inconsistent_limit_header" in item_findings[0]["notes"]
    assert item_findings[0]["indicator"] == "api_rate_limit_header_inconsistent"


def test_throttling_without_headers_is_flagged() -> None:
    observations = [
        _obs(
            "https://api.example.com/api/items",
            status_code=429,
            throttled=True,
            rate_limit_limit=None,
            rate_limit_remaining=None,
        ),
    ]
    profiles = build_endpoint_profiles(observations)
    findings = endpoint_profiles_to_findings(profiles)
    assert findings
    assert "throttled_without_headers" in findings[0]["notes"]


def test_generic_endpoint_with_no_limit_is_low() -> None:
    observations = [
        _obs(
            "https://api.example.com/static/manifest.json",
            method="GET",
            rate_limit_limit=None,
            rate_limit_remaining=None,
        )
    ]
    profiles = build_endpoint_profiles(observations)
    findings = endpoint_profiles_to_findings(profiles)
    assert findings
    assert findings[0]["severity"] == "low"
    assert findings[0]["indicator"] == "api_rate_limit_missing_generic"


def test_observation_dicts_are_accepted() -> None:
    raw = [
        {
            "url": "https://api.example.com/login",
            "method": "POST",
            "status_code": 200,
            "rate_limit_limit": None,
        },
        {
            "url": "https://api.example.com/api/profile",
            "method": "GET",
            "status_code": 200,
            "rate_limit_limit": 100,
            "rate_limit_remaining": 99,
        },
    ]
    profiles = build_endpoint_profiles(raw)
    findings = endpoint_profiles_to_findings(profiles)
    assert len(findings) == 2
    severities = sorted(f["severity"] for f in findings)
    assert severities[0] == "high"  # login (sensitive, missing)


def test_findings_sorted_by_severity() -> None:
    observations = [
        _obs("https://api.example.com/login", rate_limit_limit=None, rate_limit_remaining=None),
        _obs(
            "https://api.example.com/static/manifest.json",
            method="GET",
            rate_limit_limit=None,
            rate_limit_remaining=None,
        ),
    ]
    profiles = build_endpoint_profiles(observations)
    findings = endpoint_profiles_to_findings(profiles)
    assert findings[0]["severity"] == "high"

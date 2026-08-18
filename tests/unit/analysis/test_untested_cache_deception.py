"""Coverage for previously untested web cache deception detector."""

from __future__ import annotations

import pytest

from src.analysis.passive.detectors.detector_cache_deception import (
    _calculate_risk_score,
    _calculate_severity,
    _check_authenticated_endpoint_context,
    _check_cache_deception_url,
    _check_cache_headers,
    _check_path_normalization,
    cache_deception_detector,
)


@pytest.mark.unit
def test_dynamic_path_with_static_extension_is_flagged() -> None:
    signals = _check_cache_deception_url("https://app.example.com/account/profile.css")
    assert "dynamic_path_static_extension" in signals
    assert "mixed_dynamic_static_path" in signals
    assert "static_file_extension" in signals
    assert "dynamic_content_path" in signals


@pytest.mark.unit
def test_plain_html_path_is_not_a_deception_url() -> None:
    assert _check_cache_deception_url("https://app.example.com/about") == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://app.example.com/account/../admin.css", "path_traversal_in_url"),
        ("https://app.example.com/account//me", "double_slash_in_path"),
        ("https://app.example.com/account/%2e%2e/me", "encoded_path_traversal"),
        ("https://app.example.com/account/", "trailing_slash_variation"),
    ],
)
def test_path_normalization_signals(url: str, expected: str) -> None:
    assert expected in _check_path_normalization(url)


@pytest.mark.unit
def test_public_cache_headers_without_private() -> None:
    signals = _check_cache_headers(
        {
            "headers": {
                "Cache-Control": "public, s-maxage=86400, max-age=7200",
                "Expires": "Wed, 21 Oct 2026 07:28:00 GMT",
                "ETag": '"abc"',
            }
        }
    )
    assert "public_cache_directive" in signals
    assert "shared_cache_max_age" in signals
    assert "long_cache_max_age" in signals
    assert "missing_vary_header" in signals
    assert "expires_header_set" in signals
    assert "etag_present" in signals


@pytest.mark.unit
def test_private_cache_and_vary_on_authorization() -> None:
    signals = _check_cache_headers(
        {
            "headers": {
                "Cache-Control": "private, no-store",
                "Vary": "Authorization, Accept",
                "Pragma": "no-cache",
            }
        }
    )
    assert "public_cache_directive" not in signals
    assert "vary_header_present" in signals
    assert "vary_on_auth_header" in signals
    assert "pragma_no_cache" in signals
    assert "missing_vary_header" not in signals


@pytest.mark.unit
def test_sensitive_endpoint_publicly_cacheable() -> None:
    signals = _check_authenticated_endpoint_context(
        "https://app.example.com/billing/invoices",
        {"headers": {"Cache-Control": "public, max-age=60"}},
    )
    assert "sensitive_endpoint_publicly_cacheable" in signals
    assert "sensitive_endpoint_missing_vary" in signals


@pytest.mark.unit
def test_severity_and_risk_score_contracts() -> None:
    assert _calculate_severity(["auth_endpoint_publicly_cacheable"]) == "critical"
    assert _calculate_severity(["public_cache_directive"]) == "medium"
    assert _calculate_severity(["etag_present"]) == "low"
    assert _calculate_risk_score(["auth_endpoint_publicly_cacheable"] * 10) == 20
    assert _calculate_risk_score(["dynamic_path_static_extension"]) == 7
    assert _calculate_risk_score([]) == 0


@pytest.mark.unit
def test_detector_returns_sorted_findings_and_respects_limit() -> None:
    urls = {
        "https://app.example.com/account/me.css",
        "https://app.example.com/profile/avatar.js",
        "https://app.example.com/about",
    }
    findings = cache_deception_detector(urls, responses=[], limit=1)
    assert len(findings) == 1
    assert findings[0]["risk_score"] >= 7
    assert findings[0]["url"].endswith((".css", ".js"))


@pytest.mark.unit
def test_detector_uses_response_headers_when_url_has_no_path_signal() -> None:
    findings = cache_deception_detector(
        urls=set(),
        responses=[
            {
                "url": "https://app.example.com/oauth/authorize",
                "headers": {"Cache-Control": "public, max-age=600"},
            }
        ],
    )
    assert findings
    flat = set(findings[0]["signals"])
    assert "auth_endpoint_publicly_cacheable" in flat
    assert findings[0]["severity"] == "critical"

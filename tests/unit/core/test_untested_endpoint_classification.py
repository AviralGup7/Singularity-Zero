"""Coverage for src.core.utils.endpoint_classification."""

from __future__ import annotations

import pytest

from src.core.utils.endpoint_classification import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    filter_noise_urls,
    has_meaningful_parameters,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    is_noise_url,
    is_third_party_auth_host,
    is_tracking_param,
    meaningful_query_pairs,
    same_host_family,
    strip_tracking_params,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://a.com/metrics", "DEBUG"),
        ("https://a.com/backup.sql", "BACKUP"),
        ("https://a.com/swagger-ui", "EXPOSED"),
        ("https://a.com/static/app.js", "STATIC"),
        ("https://a.com/login", "AUTH"),
        ("https://a.com/redirect?to=x", "REDIRECT"),
        ("https://a.com/api/v1/users", "API"),
        ("https://a.com/about", "GENERAL"),
    ],
)
def test_classify_endpoint_types(url: str, expected: str) -> None:
    assert classify_endpoint(url) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://a.com/login", True),
        ("https://a.com/oauth/authorize", True),
        ("https://a.com/users", False),
    ],
)
def test_auth_flow_endpoint(url: str, expected: bool) -> None:
    assert is_auth_flow_endpoint(url) is expected


@pytest.mark.unit
def test_low_value_static_and_backup() -> None:
    assert is_low_value_endpoint("https://a.com/static/x.css") is True
    assert is_low_value_endpoint("https://a.com/api/v1/users") is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("utm_source", True),
        ("gclid", True),
        ("fbclid", True),
        ("user_id", False),
        ("", False),
    ],
)
def test_tracking_param_names(name: str, expected: bool) -> None:
    assert is_tracking_param(name) is expected


@pytest.mark.unit
def test_meaningful_query_pairs_drop_tracking() -> None:
    url = "https://a.com/p?id=1&utm_source=ad&q=search"
    pairs = meaningful_query_pairs(url)
    keys = [k for k, _ in pairs]
    assert keys == ["id", "q"]
    assert strip_tracking_params(url) == pairs
    assert has_meaningful_parameters(url) is True
    assert has_meaningful_parameters("https://a.com/p?utm_source=ad") is False


@pytest.mark.unit
def test_endpoint_signature_includes_sorted_param_names() -> None:
    sig = endpoint_signature("https://API.example.com/Users?b=2&a=1")
    assert sig.startswith("|/users|")
    assert "a" in sig and "b" in sig
    base = endpoint_base_key("https://API.example.com/Users?b=2")
    assert base == "|/users"
    hosted = endpoint_signature("https://API.example.com/Users?a=1", include_host=True)
    assert hosted.startswith("api.example.com|")


@pytest.mark.unit
def test_noise_url_and_filter() -> None:
    urls = {
        "https://cdn.example.com/app.js",
        "https://static.example.com/x",
        "https://api.example.com/v1/users",
        "https://github.com/login",
    }
    kept = filter_noise_urls(urls)
    assert kept == ["https://api.example.com/v1/users"]
    assert is_noise_url("https://facebook.com/x") is True


@pytest.mark.unit
@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("www.example.com", "api.example.com", True),
        ("a.example.co.uk", "b.example.co.uk", True),
        ("example.com", "evil.com", False),
        ("", "example.com", False),
    ],
)
def test_same_host_family(left: str, right: str, expected: bool) -> None:
    assert same_host_family(left, right) is expected


@pytest.mark.unit
def test_third_party_auth_host_respects_target_family() -> None:
    assert is_third_party_auth_host("accounts.google.com") is True
    assert is_third_party_auth_host("login.microsoftonline.com") is True
    assert is_third_party_auth_host("api.example.com") is False
    assert is_third_party_auth_host("accounts.google.com", target_host="google.com") is False

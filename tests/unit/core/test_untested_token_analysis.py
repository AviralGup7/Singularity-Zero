"""Coverage for src.core.utils.token_analysis (previously untested)."""

from __future__ import annotations

import pytest

from src.core.utils.token_analysis import (
    extract_host_candidate,
    has_remote_scheme,
    is_dangerous_scheme,
    is_internal_host_value,
    is_suspicious_path_redirect,
    looks_like_dns_callback,
    replay_likelihood,
    sort_token_targets,
    token_location_severity,
    token_shape,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdeflongsigxx",
            "jwt_like",
        ),
        ("Bearer abcdef", "bearer_token"),
        ("AKIAAAAAAAAAAAAAAAAA", "aws_access_key"),
        ("sk-test-" + ("A" * 24), "api_key"),
        ("ghp_" + ("A" * 36), "github_token"),
        ("xoxb-1234567890-abcdefghij", "slack_token"),
        ("sk_live_" + ("A" * 20), "stripe_key"),
        ("a" * 32, "hex_token"),
        ("AbCdEfGhIjKlMnOpQrStUvWxYz012345", "session_id"),
        ("abc123xyz", "oauth_code"),
        ("not-a-token", "generic"),
    ],
)
def test_token_shape_identifies_common_forms(value: str, expected: str) -> None:
    assert token_shape(value) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("location", "shapes", "repeats", "minimum"),
    [
        ("response_body", ["jwt_like"], 3, 0.7),
        ("referer_risk", [], 0, 0.5),
        ("header", [], 0, 0.3),
        ("unknown", ["jwt_like"], 0, 0.4),
    ],
)
def test_replay_likelihood_scales_with_risk(
    location: str, shapes: list[str], repeats: int, minimum: float
) -> None:
    score = replay_likelihood(location, shapes, repeats)
    assert minimum <= score <= 0.98


@pytest.mark.unit
@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("response_body", "high"),
        ("referer_risk", "high"),
        ("header", "medium"),
        ("query_parameter", "medium"),
        ("unknown", "low"),
        ("", "low"),
        ("nope", "low"),
    ],
)
def test_token_location_severity(location: str, expected: str) -> None:
    assert token_location_severity(location) == expected


@pytest.mark.unit
def test_sort_token_targets_orders_by_location_then_count() -> None:
    items = [
        {"location": "unknown", "leak_count": 1, "url": "b"},
        {"location": "response_body", "leak_count": 1, "url": "a"},
        {"location": "response_body", "leak_count": 5, "url": "c"},
        {"location": "header", "leak_count": 2, "url": "d"},
    ]
    ordered = sort_token_targets(items)
    assert ordered[0]["url"] == "c"
    assert ordered[1]["url"] == "a"
    assert ordered[-1]["location"] == "unknown"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://api.example.com/v1", "api.example.com"),
        ("//cdn.example.net/x", "cdn.example.net"),
        ("foo.bar.example.com", "foo.bar.example.com"),
        ("not a host", ""),
        ("", ""),
    ],
)
def test_extract_host_candidate(value: str, expected: str) -> None:
    assert extract_host_candidate(value) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["file:///etc/passwd", "ftp://evil", "gopher://x", "FILE://X"],
)
def test_dangerous_schemes(value: str) -> None:
    assert is_dangerous_scheme(value) is True


@pytest.mark.unit
@pytest.mark.parametrize("value", ["https://ok", "http://ok", "not-a-url"])
def test_non_dangerous_schemes(value: str) -> None:
    assert is_dangerous_scheme(value) is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://a.com", True),
        ("http://a.com", True),
        ("ftp://a.com", True),
        ("relative/path", False),
    ],
)
def test_has_remote_scheme(value: str, expected: bool) -> None:
    assert has_remote_scheme(value) is expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "localhost",
        "http://192.168.1.4/admin",
        "10.0.0.8",
        "169.254.169.254/latest/meta-data",
        "metadata.google.internal",
        "::1",
        "2130706433",
    ],
)
def test_internal_hosts_detected(value: str) -> None:
    assert is_internal_host_value(value) is True


@pytest.mark.unit
def test_public_host_is_not_internal() -> None:
    assert is_internal_host_value("https://example.com/login") is False


@pytest.mark.unit
def test_dns_callback_requires_public_multi_label_host() -> None:
    assert looks_like_dns_callback("abc.def.burpcollaborator.net") is True
    assert looks_like_dns_callback("localhost") is False
    assert looks_like_dns_callback("not a host") is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/admin/users", True),
        ("./api/token", True),
        ("../internal/debug", True),
        ("/public/about", False),
        ("https://example.com/admin", False),
    ],
)
def test_suspicious_path_redirect(value: str, expected: bool) -> None:
    assert is_suspicious_path_redirect(value) is expected

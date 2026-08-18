"""Coverage for previously untested API spec discovery helpers."""

from __future__ import annotations

import pytest

from src.recon.api_specs.discovery import (
    _candidate_spec_urls,
    _candidate_spec_urls_enhanced,
    _normalize_base,
    extract_auth_headers_from_js_parsers,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("", ""),
        ("  ", ""),
        ("Example.COM", "https://example.com"),
        ("https://A.example.com/v1", "https://a.example.com/v1"),
        ("http://localhost:8080", "http://localhost:8080"),
    ],
)
def test_normalize_base(host: str, expected: str) -> None:
    assert _normalize_base(host) == expected


@pytest.mark.unit
def test_candidate_spec_urls_include_defaults_and_extra() -> None:
    urls = _candidate_spec_urls("example.com", ["custom.json", "", "openapi.json"])
    assert "https://example.com/openapi.json" in urls
    assert "https://example.com/swagger.yaml" in urls
    assert "https://example.com/custom.json" in urls
    assert urls.count("https://example.com/openapi.json") == 1
    assert all(u.startswith("https://example.com/") for u in urls)


@pytest.mark.unit
def test_candidate_spec_urls_empty_or_unsafe_host() -> None:
    assert _candidate_spec_urls("", None) == []
    assert _candidate_spec_urls("   ", ["x"]) == []


@pytest.mark.unit
def test_candidate_spec_urls_enhanced_adds_more_families() -> None:
    basic = set(_candidate_spec_urls("example.com", None))
    enhanced = set(_candidate_spec_urls_enhanced("example.com"))
    assert basic.issubset(enhanced)
    assert len(enhanced) > len(basic)
    joined = " ".join(enhanced)
    assert "asyncapi" in joined or "graphql" in joined or ".proto" in joined


@pytest.mark.unit
def test_candidate_spec_urls_enhanced_can_disable_families() -> None:
    slim = _candidate_spec_urls_enhanced(
        "example.com",
        include_asyncapi=False,
        include_graphql_sdl=False,
        include_proto=False,
        include_grpc_web=False,
        include_thrift=False,
        include_avro=False,
        include_grpc_paths=False,
    )
    fat = _candidate_spec_urls_enhanced("example.com")
    assert len(slim) < len(fat)


@pytest.mark.unit
def test_extract_auth_headers_from_nested_js_and_regex() -> None:
    parsed = {
        "endpoints": [
            {
                "headers": {
                    "Authorization": "Bearer nestedtok",
                    "X-Api-Key": "k-123",
                }
            }
        ],
        "blob": "authorization: Bearer regexTok999",
    }
    headers = extract_auth_headers_from_js_parsers(parsed)
    assert headers["authorization"] in {"Bearer nestedtok", "authorization: Bearer regexTok999"}
    assert "x-api-key" in headers
    assert headers["x-api-key"]


@pytest.mark.unit
def test_extract_auth_headers_api_key_regex_and_empty_inputs() -> None:
    assert extract_auth_headers_from_js_parsers(None) == {}
    assert extract_auth_headers_from_js_parsers("nope") == {}  # type: ignore[arg-type]
    headers = extract_auth_headers_from_js_parsers({"note": "api-key: abcDEF123"})
    assert headers.get("x-api-key") == "abcDEF123"


@pytest.mark.unit
def test_extra_paths_without_leading_slash_are_normalized() -> None:
    urls = _candidate_spec_urls("https://shop.example.com/app", ["docs/openapi.json"])
    assert "https://shop.example.com/docs/openapi.json" in urls

"""Tests for fuzzing HTTP payload generator module."""

from src.fuzzing.payload_generator_http import (
    HEADER_PAYLOADS,
    INJECTABLE_HEADERS,
    _infer_body_fields_from_url,
    generate_body_payloads,
    generate_header_payloads,
)


class TestInjectableHeaders:
    def test_injectable_headers_is_list(self) -> None:
        assert isinstance(INJECTABLE_HEADERS, list)

    def test_injectable_headers_not_empty(self) -> None:
        assert len(INJECTABLE_HEADERS) > 0

    def test_contains_x_forwarded_for(self) -> None:
        assert "X-Forwarded-For" in INJECTABLE_HEADERS

    def test_contains_x_forwarded_host(self) -> None:
        assert "X-Forwarded-Host" in INJECTABLE_HEADERS

    def test_contains_origin(self) -> None:
        assert "Origin" in INJECTABLE_HEADERS

    def test_contains_x_http_method_override(self) -> None:
        assert "X-HTTP-Method-Override" in INJECTABLE_HEADERS

    def test_contains_x_original_url(self) -> None:
        assert "X-Original-URL" in INJECTABLE_HEADERS

    def test_contains_host(self) -> None:
        assert "Host" in INJECTABLE_HEADERS

    def test_contains_referer(self) -> None:
        assert "Referer" in INJECTABLE_HEADERS


class TestHeaderPayloads:
    def test_header_payloads_is_dict(self) -> None:
        assert isinstance(HEADER_PAYLOADS, dict)

    def test_has_x_forwarded_for_payloads(self) -> None:
        assert "X-Forwarded-For" in HEADER_PAYLOADS

    def test_has_x_forwarded_host_payloads(self) -> None:
        assert "X-Forwarded-Host" in HEADER_PAYLOADS

    def test_has_origin_payloads(self) -> None:
        assert "Origin" in HEADER_PAYLOADS

    def test_has_x_http_method_override_payloads(self) -> None:
        assert "X-HTTP-Method-Override" in HEADER_PAYLOADS

    def test_xff_payload_has_localhost(self) -> None:
        payloads = HEADER_PAYLOADS["X-Forwarded-For"]
        variants = [p["variant"] for p in payloads]
        assert "127.0.0.1" in variants

    def test_xff_payload_has_metadata_ip(self) -> None:
        payloads = HEADER_PAYLOADS["X-Forwarded-For"]
        variants = [p["variant"] for p in payloads]
        assert "169.254.169.254" in variants

    def test_origin_payload_has_evil_com(self) -> None:
        payloads = HEADER_PAYLOADS["Origin"]
        variants = [p["variant"] for p in payloads]
        assert "https://evil.com" in variants

    def test_method_override_has_delete(self) -> None:
        payloads = HEADER_PAYLOADS["X-HTTP-Method-Override"]
        variants = [p["variant"] for p in payloads]
        assert "DELETE" in variants

    def test_each_payload_has_header_key(self) -> None:
        for header_name, payloads in HEADER_PAYLOADS.items():
            for payload in payloads:
                assert "header" in payload

    def test_each_payload_has_variant_key(self) -> None:
        for header_name, payloads in HEADER_PAYLOADS.items():
            for payload in payloads:
                assert "variant" in payload

    def test_each_payload_has_reason_key(self) -> None:
        for header_name, payloads in HEADER_PAYLOADS.items():
            for payload in payloads:
                assert "reason" in payload


class TestGenerateHeaderPayloads:
    def test_returns_list(self) -> None:
        result = generate_header_payloads(["https://example.com/api/v1/users"])
        assert isinstance(result, list)

    def test_result_has_url_key(self) -> None:
        result = generate_header_payloads(["https://example.com/api/v1/users"])
        for item in result:
            assert "url" in item

    def test_result_has_endpoint_key(self) -> None:
        result = generate_header_payloads(["https://example.com/api/v1/users"])
        for item in result:
            assert "endpoint_key" in item

    def test_result_has_header_suggestions_key(self) -> None:
        result = generate_header_payloads(["https://example.com/api/v1/users"])
        for item in result:
            assert "header_suggestions" in item

    def test_api_endpoints_get_relevant_headers(self) -> None:
        result = generate_header_payloads(["https://example.com/api/v1/users"])
        if result:
            headers = [s["header"] for s in result[0]["header_suggestions"]]
            assert "X-Forwarded-For" in headers

    def test_admin_endpoints_get_admin_headers(self) -> None:
        result = generate_header_payloads(["https://example.com/admin/dashboard"])
        if result:
            headers = [s["header"] for s in result[0]["header_suggestions"]]
            assert "X-Forwarded-For" in headers

    def test_respects_limit(self) -> None:
        urls = [f"https://example.com/api{i}?id=1" for i in range(50)]
        result = generate_header_payloads(urls, limit=3)
        assert len(result) <= 3

    def test_skips_noise_urls(self) -> None:
        result = generate_header_payloads(["https://example.com/robots.txt"])
        assert len(result) == 0

    def test_empty_urls_returns_empty(self) -> None:
        result = generate_header_payloads([])
        assert result == []

    def test_deduplicates_endpoint_keys(self) -> None:
        urls = [
            "https://example.com/api?id=1",
            "https://example.com/api?id=2",
        ]
        result = generate_header_payloads(urls)
        endpoint_keys = [item["endpoint_key"] for item in result]
        assert len(endpoint_keys) == len(set(endpoint_keys))


class TestGenerateBodyPayloads:
    def test_returns_list(self) -> None:
        result = generate_body_payloads(["https://example.com/api/v1/users"])
        assert isinstance(result, list)

    def test_result_has_body_suggestions_key(self) -> None:
        result = generate_body_payloads(["https://example.com/api/v1/users"])
        for item in result:
            assert "body_suggestions" in item

    def test_only_targets_api_endpoints(self) -> None:
        result = generate_body_payloads(["https://example.com/static/page"])
        assert len(result) == 0

    def test_targets_api_v1_paths(self) -> None:
        result = generate_body_payloads(["https://example.com/api/v1/users"])
        assert len(result) > 0

    def test_skips_noise_urls(self) -> None:
        result = generate_body_payloads(["https://example.com/robots.txt"])
        assert len(result) == 0

    def test_empty_urls_returns_empty(self) -> None:
        result = generate_body_payloads([])
        assert result == []


class TestInferBodyFields:
    def test_user_path_infers_user_fields(self) -> None:
        fields = _infer_body_fields_from_url("https://example.com/api/v1/users")
        field_names = [f[0] for f in fields]
        assert "user_id" in field_names

    def test_order_path_infers_order_fields(self) -> None:
        fields = _infer_body_fields_from_url("https://example.com/api/v1/orders")
        field_names = [f[0] for f in fields]
        assert "order_id" in field_names

    def test_login_path_infers_auth_fields(self) -> None:
        fields = _infer_body_fields_from_url("https://example.com/api/v1/login")
        field_names = [f[0] for f in fields]
        assert "username" in field_names

    def test_upload_path_infers_file_fields(self) -> None:
        fields = _infer_body_fields_from_url("https://example.com/api/v1/upload")
        field_names = [f[0] for f in fields]
        assert "file_name" in field_names

    def test_unknown_path_returns_empty(self) -> None:
        fields = _infer_body_fields_from_url("https://example.com/unknown/path")
        assert fields == []

    def test_fields_are_unique(self) -> None:
        fields = _infer_body_fields_from_url("https://example.com/api/v1/users/profile")
        names = [f[0] for f in fields]
        assert len(names) == len(set(names))

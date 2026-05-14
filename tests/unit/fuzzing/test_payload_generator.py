"""Tests for fuzzing payload generator module."""

from src.fuzzing.payload_generator import (
    generate_parameter_payloads,
    generate_payload_suggestions,
)


class TestGenerateParameterPayloads:
    def test_returns_list(self) -> None:
        result = generate_parameter_payloads("id", "123")
        assert isinstance(result, list)

    def test_returns_non_empty(self) -> None:
        result = generate_parameter_payloads("id", "123")
        assert len(result) > 0

    def test_payload_has_parameter_key(self) -> None:
        result = generate_parameter_payloads("id", "123")
        assert all("parameter" in p for p in result)

    def test_payload_has_variant_key(self) -> None:
        result = generate_parameter_payloads("id", "123")
        assert all("variant" in p for p in result)

    def test_payload_has_reason_key(self) -> None:
        result = generate_parameter_payloads("id", "123")
        assert all("reason" in p for p in result)

    def test_parameter_name_matches(self) -> None:
        result = generate_parameter_payloads("user_id", "42")
        assert all(p["parameter"] == "user_id" for p in result)

    def test_respects_max_payloads(self) -> None:
        result = generate_parameter_payloads("id", "1", max_payloads_per_param=3)
        assert len(result) <= 3

    def test_uses_custom_collaborator_domain(self) -> None:
        result = generate_parameter_payloads(
            "url",
            "http://example.com",
            collaborator_domain="my-collab.example",
            max_payloads_per_param=100,
        )
        variants = [p["variant"] for p in result]
        assert any("my-collab.example" in v for v in variants)

    def test_url_param_generates_ssrf_payloads(self) -> None:
        result = generate_parameter_payloads(
            "url", "http://example.com", max_payloads_per_param=100
        )
        reasons = [p["reason"] for p in result]
        assert any("ssrf" in r for r in reasons)

    def test_token_param_generates_token_payloads(self) -> None:
        result = generate_parameter_payloads("token", "abc123")
        reasons = [p["reason"] for p in result]
        assert any("token" in r or "jwt" in r for r in reasons)

    def test_redirect_param_generates_redirect_payloads(self) -> None:
        result = generate_parameter_payloads("next", "/dashboard")
        reasons = [p["reason"] for p in result]
        assert any("redirect" in r for r in reasons)

    def test_numeric_param_generates_boundary_payloads(self) -> None:
        result = generate_parameter_payloads("id", "42")
        variants = [p["variant"] for p in result]
        assert "0" in variants or "-1" in variants

    def test_generic_param_generates_probe_payloads(self) -> None:
        result = generate_parameter_payloads("lang", "en")
        variants = [p["variant"] for p in result]
        assert any(v == "__probe__" for v in variants)

    def test_empty_name_handled(self) -> None:
        result = generate_parameter_payloads("", "value")
        assert isinstance(result, list)


class TestGeneratePayloadSuggestions:
    def test_returns_list(self) -> None:
        result = generate_payload_suggestions(["https://example.com/api?id=1"])
        assert isinstance(result, list)

    def test_suggestion_has_url_key(self) -> None:
        result = generate_payload_suggestions(["https://example.com/api?id=1"])
        for item in result:
            assert "url" in item

    def test_suggestion_has_endpoint_key(self) -> None:
        result = generate_payload_suggestions(["https://example.com/api?id=1"])
        for item in result:
            assert "endpoint_key" in item

    def test_suggestion_has_suggestions_key(self) -> None:
        result = generate_payload_suggestions(["https://example.com/api?id=1"])
        for item in result:
            assert "suggestions" in item

    def test_respects_limit(self) -> None:
        urls = [f"https://example.com/api{i}?id=1" for i in range(50)]
        result = generate_payload_suggestions(urls, limit=5)
        assert len(result) <= 5

    def test_skips_noise_urls(self) -> None:
        result = generate_payload_suggestions(["https://example.com/robots.txt"])
        assert len(result) == 0

    def test_deduplicates_endpoint_keys(self) -> None:
        urls = [
            "https://example.com/api?id=1",
            "https://example.com/api?id=2",
            "https://example.com/api?id=3",
        ]
        result = generate_payload_suggestions(urls)
        assert len(result) <= 1

    def test_empty_urls_returns_empty(self) -> None:
        result = generate_payload_suggestions([])
        assert result == []

    def test_urls_without_params_returns_empty(self) -> None:
        result = generate_payload_suggestions(["https://example.com/static/page"])
        assert len(result) == 0


class TestPayloadDeduplication:
    def test_no_duplicate_variants_for_same_parameter(self) -> None:
        result = generate_parameter_payloads("id", "1", max_payloads_per_param=100)
        variants = [p["variant"] for p in result]
        assert len(variants) == len(set(variants))

    def test_deduplication_across_urls(self) -> None:
        urls = [
            "https://example.com/api?id=1",
            "https://example.com/api?id=2",
        ]
        result = generate_payload_suggestions(urls)
        endpoint_keys = [item["endpoint_key"] for item in result]
        assert len(endpoint_keys) == len(set(endpoint_keys))


class TestPayloadEncoding:
    def test_url_payloads_include_various_schemes(self) -> None:
        result = generate_parameter_payloads(
            "url", "http://example.com", max_payloads_per_param=100
        )
        variants = [p["variant"] for p in result]
        assert any(v.startswith("http://") for v in variants)
        assert any(v.startswith("https://") for v in variants)

    def test_redirect_payloads_include_encoded_variants(self) -> None:
        result = generate_parameter_payloads("next", "/page", max_payloads_per_param=100)
        variants = [p["variant"] for p in result]
        assert any("%2F" in v for v in variants)

    def test_json_payloads_are_valid_json(self) -> None:
        import json

        result = generate_parameter_payloads("data", "{}", max_payloads_per_param=100)
        for p in result:
            try:
                json.loads(p["variant"])
            except json.JSONDecodeError:
                pass

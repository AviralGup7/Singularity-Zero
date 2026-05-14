import pytest

from src.api_tests.apitester.results.builder import build_api_test_result
from src.api_tests.apitester.results.formatting import clean_bool, clean_number, clean_text


class TestCleanText:
    @pytest.mark.unit
    def test_normal_string(self):
        assert clean_text("hello") == "hello"

    @pytest.mark.unit
    def test_strips_whitespace(self):
        assert clean_text("  hello  ") == "hello"

    @pytest.mark.unit
    def test_none_returns_default(self):
        assert clean_text(None) == ""

    @pytest.mark.unit
    def test_empty_string_returns_default(self):
        assert clean_text("") == ""

    @pytest.mark.unit
    def test_custom_default(self):
        assert clean_text(None, "n/a") == "n/a"

    @pytest.mark.unit
    def test_empty_string_custom_default(self):
        assert clean_text("", "default") == "default"

    @pytest.mark.unit
    def test_non_string_value(self):
        assert clean_text(42) == "42"

    @pytest.mark.unit
    def test_boolean_true(self):
        assert clean_text(True) == "True"

    @pytest.mark.unit
    def test_boolean_false(self):
        assert clean_text(False) == ""


class TestCleanBool:
    @pytest.mark.unit
    def test_true_returns_yes(self):
        assert clean_bool(True) == "yes"

    @pytest.mark.unit
    def test_false_returns_no(self):
        assert clean_bool(False) == "no"

    @pytest.mark.unit
    def test_none_returns_unknown(self):
        assert clean_bool(None) == "unknown"

    @pytest.mark.unit
    def test_empty_string_returns_unknown(self):
        assert clean_bool("") == "unknown"

    @pytest.mark.unit
    def test_zero_returns_unknown(self):
        assert clean_bool(0) == "unknown"

    @pytest.mark.unit
    def test_one_returns_unknown(self):
        assert clean_bool(1) == "unknown"

    @pytest.mark.unit
    def test_string_returns_unknown(self):
        assert clean_bool("yes") == "unknown"


class TestCleanNumber:
    @pytest.mark.unit
    def test_integer(self):
        assert clean_number(42) == "42.0"

    @pytest.mark.unit
    def test_float(self):
        assert clean_number(3.14159) == "3.142"

    @pytest.mark.unit
    def test_none_returns_na(self):
        assert clean_number(None) == "n/a"

    @pytest.mark.unit
    def test_empty_string_returns_na(self):
        assert clean_number("") == "n/a"

    @pytest.mark.unit
    def test_string_number(self):
        assert clean_number("3.14") == "3.14"

    @pytest.mark.unit
    def test_digits_zero(self):
        assert clean_number(42.7, digits=0) == "43"

    @pytest.mark.unit
    def test_digits_one(self):
        assert clean_number(3.14159, digits=1) == "3.1"

    @pytest.mark.unit
    def test_digits_two(self):
        assert clean_number(3.14159, digits=2) == "3.14"

    @pytest.mark.unit
    def test_invalid_string_returns_na(self):
        assert clean_number("not_a_number") == "not_a_number"

    @pytest.mark.unit
    def test_zero(self):
        assert clean_number(0) == "0.0"

    @pytest.mark.unit
    def test_negative(self):
        assert clean_number(-5.5) == "-5.5"


class TestBuildApiTestResult:
    @pytest.mark.unit
    def test_basic_result(self):
        item = {
            "title": "Potential IDOR",
            "request_context": {
                "baseline_url": "https://api.example.com/users/123",
                "mutated_url": "https://api.example.com/users/456",
                "parameter": "user_id",
                "variant": "456",
                "method": "GET",
            },
        }
        result = build_api_test_result(item)
        assert result["title"] == "Potential IDOR"
        assert result["baseline_url"] == "https://api.example.com/users/123"
        assert result["variant_url"] == "https://api.example.com/users/456"
        assert result["parameter"] == "user_id"
        assert result["variant"] == "456"

    @pytest.mark.unit
    def test_result_has_summary(self):
        item = {
            "title": "Test",
            "request_context": {
                "baseline_url": "https://api.example.com/a",
                "mutated_url": "https://api.example.com/b",
                "parameter": "id",
                "variant": "2",
                "method": "POST",
            },
        }
        result = build_api_test_result(item)
        assert "summary" in result
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    @pytest.mark.unit
    def test_summary_contains_expected_fields(self):
        item = {
            "title": "Auth Bypass",
            "request_context": {
                "baseline_url": "https://api.example.com/login",
                "mutated_url": "https://api.example.com/login",
                "parameter": "token",
                "variant": "invalid",
                "method": "POST",
            },
        }
        result = build_api_test_result(item)
        summary = result["summary"]
        assert "Observed Baseline URL" in summary
        assert "Observed Variant URL" in summary
        assert "Observed Method" in summary
        assert "Observed Mutation" in summary
        assert "Status Changed" in summary
        assert "Redirect Changed" in summary
        assert "Content Changed" in summary
        assert "Trust Boundary Shift" in summary
        assert "Body Similarity" in summary
        assert "Length Delta" in summary
        assert "Shared Key Fields" in summary
        assert "Replay ID" in summary

    @pytest.mark.unit
    def test_empty_request_context(self):
        item = {
            "title": "Empty Context",
            "request_context": {},
        }
        result = build_api_test_result(item)
        assert result["title"] == "Empty Context"
        assert result["parameter"] == "n/a"
        assert result["variant"] == "n/a"

    @pytest.mark.unit
    def test_missing_request_context(self):
        item = {
            "title": "No Context",
        }
        result = build_api_test_result(item)
        assert result["title"] == "No Context"

    @pytest.mark.unit
    def test_none_request_context(self):
        item = {
            "title": "None Context",
            "request_context": None,
        }
        result = build_api_test_result(item)
        assert result["title"] == "None Context"

    @pytest.mark.unit
    def test_result_keys(self):
        item = {
            "title": "Test",
            "request_context": {
                "baseline_url": "https://example.com/a",
                "mutated_url": "https://example.com/b",
                "parameter": "p",
                "variant": "v",
                "method": "GET",
            },
        }
        result = build_api_test_result(item)
        expected_keys = {"title", "summary", "baseline_url", "variant_url", "parameter", "variant"}
        assert set(result.keys()) == expected_keys

    @pytest.mark.unit
    def test_all_values_are_strings(self):
        item = {
            "title": "Test",
            "request_context": {
                "baseline_url": "https://example.com/a",
                "mutated_url": "https://example.com/b",
                "parameter": "p",
                "variant": "v",
                "method": "GET",
            },
        }
        result = build_api_test_result(item)
        for key, value in result.items():
            assert isinstance(value, str)

    @pytest.mark.unit
    def test_with_evidence(self):
        item = {
            "title": "With Evidence",
            "request_context": {
                "baseline_url": "https://api.example.com/users/1",
                "mutated_url": "https://api.example.com/users/2",
                "parameter": "user_id",
                "variant": "2",
                "method": "GET",
            },
            "evidence": {
                "diff_summary": {
                    "status_changed": True,
                    "content_changed": False,
                    "body_similarity": 0.85,
                    "length_delta": 150,
                },
                "shared_key_fields": ["id", "name", "email"],
            },
            "replay_id": "replay-123",
        }
        result = build_api_test_result(item)
        assert result["title"] == "With Evidence"
        assert "yes" in result["summary"]
        assert "no" in result["summary"]

    @pytest.mark.unit
    def test_with_trust_boundary_shift(self):
        item = {
            "title": "Trust Boundary",
            "request_context": {
                "baseline_url": "https://api.example.com/a",
                "mutated_url": "https://api.example.com/b",
                "parameter": "p",
                "variant": "v",
                "method": "GET",
            },
            "trust_boundary_shift": True,
        }
        result = build_api_test_result(item)
        assert "Trust Boundary Shift: yes" in result["summary"]

    @pytest.mark.unit
    def test_method_defaults_to_get(self):
        item = {
            "title": "Default Method",
            "request_context": {
                "baseline_url": "https://api.example.com/a",
                "mutated_url": "https://api.example.com/b",
                "parameter": "p",
                "variant": "v",
            },
        }
        result = build_api_test_result(item)
        assert "Observed Method: GET" in result["summary"]

    @pytest.mark.unit
    def test_method_uppercase(self):
        item = {
            "title": "Post Method",
            "request_context": {
                "baseline_url": "https://api.example.com/a",
                "mutated_url": "https://api.example.com/b",
                "parameter": "p",
                "variant": "v",
                "method": "post",
            },
        }
        result = build_api_test_result(item)
        assert "Observed Method: POST" in result["summary"]

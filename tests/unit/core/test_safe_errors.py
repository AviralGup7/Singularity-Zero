"""Unit tests for core.utils.safe_errors module."""

import unittest

import pytest

from src.core.utils.safe_errors import (
    redact_sensitive_headers,
    safe_error_message,
    sanitize_log_message,
)


@pytest.mark.unit
class TestSafeErrorMessage(unittest.TestCase):
    def test_normal_error_passes_through(self) -> None:
        exc = ValueError("Something went wrong")
        result = safe_error_message(exc)
        self.assertEqual(result, "Something went wrong")

    def test_simple_exception_message(self) -> None:
        exc = RuntimeError("Connection refused")
        result = safe_error_message(exc)
        self.assertEqual(result, "Connection refused")

    def test_redacts_file_paths_with_py_extension(self) -> None:
        exc = Exception("Error at /app/core/utils/handler.py line 42: something failed")
        result = safe_error_message(exc)
        self.assertNotIn("/app/core/utils/handler.py", result)
        self.assertIn("[path redacted]", result)

    def test_redacts_file_paths_with_ts_extension(self) -> None:
        exc = Exception("Error at /src/index.ts not found")
        result = safe_error_message(exc)
        self.assertNotIn("/src/index.ts", result)

    def test_redacts_file_paths_with_js_extension(self) -> None:
        exc = Exception("Error at /lib/module.js error")
        result = safe_error_message(exc)
        self.assertNotIn("/lib/module.js", result)

    def test_redacts_site_packages_paths(self) -> None:
        exc = Exception("Error at /usr/lib/python3.9/site-packages/requests/api.py line 10")
        result = safe_error_message(exc)
        self.assertNotIn("site-packages", result)

    def test_redacts_lib_python_paths(self) -> None:
        exc = Exception("Error at /usr/lib/python3.9/os.py line 5")
        result = safe_error_message(exc)
        self.assertNotIn("lib/python", result)

    def test_redacts_credential_patterns_sk_prefix(self) -> None:
        exc = Exception("Invalid key: sk-abc123def456ghi789jkl012mno345")
        result = safe_error_message(exc)
        self.assertNotIn("sk-abc123def456ghi789jkl012mno345", result)
        self.assertIn("[credential redacted]", result)

    def test_redacts_credential_patterns_ghp_prefix(self) -> None:
        exc = Exception("Token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef used")
        result = safe_error_message(exc)
        self.assertNotIn("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", result)

    def test_redacts_credential_patterns_aws_key(self) -> None:
        exc = Exception("AKIAIOSFODNN7EXAMPLE found in config")
        result = safe_error_message(exc)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)

    def test_redacts_key_equals_pattern(self) -> None:
        exc = Exception("key=ABCDEFGHIJKLMNOPQRSTUVWXyz123456 is invalid")
        result = safe_error_message(exc)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXyz123456", result)

    def test_redacts_secret_equals_pattern(self) -> None:
        exc = Exception("secret=MySecretValue1234567890abcdef is wrong")
        result = safe_error_message(exc)
        self.assertNotIn("MySecretValue1234567890abcdef", result)

    def test_redacts_api_key_pattern(self) -> None:
        exc = Exception("api_key: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
        result = safe_error_message(exc)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", result)

    def test_redacts_bearer_token_pattern(self) -> None:
        exc = Exception("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        result = safe_error_message(exc)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", result)

    def test_redacts_basic_auth_pattern(self) -> None:
        exc = Exception("Basic dXNlcjpwYXNzd29yZA==")
        result = safe_error_message(exc)
        self.assertIn("[redacted]", result)

    def test_redacts_token_equals_pattern(self) -> None:
        exc = Exception("token=ABCDEFGHIJKLMNOP1234567890abcdef is expired")
        result = safe_error_message(exc)
        self.assertNotIn("ABCDEFGHIJKLMNOP1234567890abcdef", result)

    def test_redacts_password_equals_pattern(self) -> None:
        exc = Exception("password=SuperSecretPassword123 is wrong")
        result = safe_error_message(exc)
        self.assertNotIn("SuperSecretPassword123", result)

    def test_redacts_credential_equals_pattern(self) -> None:
        exc = Exception("credential=ABCDEF1234567890ABCDEF1234567890 leaked")
        result = safe_error_message(exc)
        self.assertNotIn("ABCDEF1234567890ABCDEF1234567890", result)

    def test_redacts_auth_equals_pattern(self) -> None:
        exc = Exception("auth=ABCDEF1234567890ABCDEF1234567890 invalid")
        result = safe_error_message(exc)
        self.assertNotIn("ABCDEF1234567890ABCDEF1234567890", result)

    def test_strips_traceback_pattern(self) -> None:
        exc = Exception("Traceback (most recent call last)\n  File test")
        result = safe_error_message(exc)
        self.assertNotIn("Traceback (most recent call last)", result)

    def test_strips_file_line_pattern(self) -> None:
        exc = Exception('File "test.py", line 10')
        result = safe_error_message(exc)
        self.assertNotIn('File "test.py", line 10', result)

    def test_empty_exception_message_returns_default(self) -> None:
        exc = Exception("")
        result = safe_error_message(exc)
        self.assertEqual(result, "An unexpected error occurred")

    def test_none_like_exception_handled(self) -> None:
        class NoneStrException(Exception):
            def __str__(self) -> str:
                return ""

        exc = NoneStrException()
        result = safe_error_message(exc)
        self.assertEqual(result, "An unexpected error occurred")

    def test_whitespace_only_message_returns_default(self) -> None:
        exc = Exception("   \n\t  ")
        result = safe_error_message(exc)
        self.assertEqual(result, "An unexpected error occurred")

    def test_various_exception_types(self) -> None:
        for exc_cls in [ValueError, RuntimeError, TypeError, KeyError, OSError]:
            exc = exc_cls("Test error message")
            result = safe_error_message(exc)
            self.assertIn("Test error message", result)

    def test_exception_with_no_args(self) -> None:
        exc = Exception()
        result = safe_error_message(exc)
        self.assertEqual(result, "An unexpected error occurred")

    def test_multiple_sensitive_patterns_redacted(self) -> None:
        exc = Exception(
            "Error in /app/handler.py: api_key=ABCDEFGHIJKLMNOP1234567890abcdef and "
            "password=MySecretPassword1234567890 both failed"
        )
        result = safe_error_message(exc)
        self.assertNotIn("api_key=ABCDEFGHIJKLMNOP1234567890abcdef", result)
        self.assertNotIn("MySecretPassword1234567890", result)
        self.assertNotIn("/app/handler.py", result)

    def test_non_sensitive_path_not_redacted(self) -> None:
        exc = Exception("File not found at /data/results/output.txt")
        result = safe_error_message(exc)
        self.assertIn("/data/results/output.txt", result)

    def test_colon_sensitive_pattern_redacted(self) -> None:
        exc = Exception("token: ABCDEFGHIJKLMNOP12345678 expired")
        result = safe_error_message(exc)
        self.assertNotIn("ABCDEFGHIJKLMNOP12345678", result)


@pytest.mark.unit
class TestSanitizeLogMessage(unittest.TestCase):
    def test_normal_message_unchanged(self) -> None:
        result = sanitize_log_message("Request processed successfully")
        self.assertEqual(result, "Request processed successfully")

    def test_redacts_authorization_header(self) -> None:
        result = sanitize_log_message("authorization:Bearer secret-token-123")
        self.assertIn("authorization:", result)
        self.assertNotIn("secret-token-123", result)

    def test_redacts_cookie_header(self) -> None:
        result = sanitize_log_message("cookie: session_id=abc123def456")
        self.assertIn("cookie:", result)
        self.assertNotIn("abc123def456", result)

    def test_redacts_x_api_key_header(self) -> None:
        result = sanitize_log_message("x-api-key: my-secret-api-key-value")
        self.assertIn("x-api-key:", result)
        self.assertNotIn("my-secret-api-key-value", result)

    def test_redacts_x_secret_key_header(self) -> None:
        result = sanitize_log_message("x-secret-key: super-secret")
        self.assertNotIn("super-secret", result)

    def test_redacts_x_access_token_header(self) -> None:
        result = sanitize_log_message("x-access-token: token-value-123")
        self.assertNotIn("token-value-123", result)

    def test_redacts_x_auth_token_header(self) -> None:
        result = sanitize_log_message("x-auth-token: auth-value-456")
        self.assertNotIn("auth-value-456", result)

    def test_redacts_bearer_token(self) -> None:
        result = sanitize_log_message("Using Bearer eyJhbGciOiJIUzI1NiJ9")
        self.assertIn("Bearer", result)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", result)

    def test_redacts_basic_auth(self) -> None:
        result = sanitize_log_message("Using Basic dXNlcjpwYXNz")
        self.assertIn("Basic", result)
        self.assertNotIn("dXNlcjpwYXNz", result)

    def test_redacts_credential_patterns(self) -> None:
        result = sanitize_log_message("Found sk-abc123def456ghi789 in logs")
        self.assertNotIn("sk-abc123def456ghi789", result)

    def test_multiple_sensitive_values_redacted(self) -> None:
        result = sanitize_log_message(
            "authorization: secret1 and cookie: secret2 and x-api-key: secret3"
        )
        self.assertNotIn("secret1", result)
        self.assertNotIn("secret2", result)
        self.assertNotIn("secret3", result)

    def test_empty_message_returns_empty(self) -> None:
        result = sanitize_log_message("")
        self.assertEqual(result, "")

    def test_case_insensitive_header_matching(self) -> None:
        result = sanitize_log_message("AUTHORIZATION: secret-value")
        self.assertNotIn("secret-value", result)


@pytest.mark.unit
class TestRedactSensitiveHeaders(unittest.TestCase):
    def test_non_sensitive_headers_unchanged(self) -> None:
        headers = {"Content-Type": "application/json", "Accept": "*/*"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result, headers)

    def test_authorization_header_redacted(self) -> None:
        headers = {"Authorization": "Bearer secret-token"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["Authorization"], "[REDACTED]")

    def test_cookie_header_redacted(self) -> None:
        headers = {"Cookie": "session=abc123"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["Cookie"], "[REDACTED]")

    def test_x_api_key_header_redacted(self) -> None:
        headers = {"X-API-Key": "my-api-key-value"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["X-API-Key"], "[REDACTED]")

    def test_x_secret_key_header_redacted(self) -> None:
        headers = {"X-Secret-Key": "secret-value"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["X-Secret-Key"], "[REDACTED]")

    def test_x_access_token_header_redacted(self) -> None:
        headers = {"X-Access-Token": "access-token-value"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["X-Access-Token"], "[REDACTED]")

    def test_x_auth_token_header_redacted(self) -> None:
        headers = {"X-Auth-Token": "auth-token-value"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["X-Auth-Token"], "[REDACTED]")

    def test_mixed_headers(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer secret",
            "Accept": "*/*",
            "Cookie": "session=abc",
        }
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["Content-Type"], "application/json")
        self.assertEqual(result["Authorization"], "[REDACTED]")
        self.assertEqual(result["Accept"], "*/*")
        self.assertEqual(result["Cookie"], "[REDACTED]")

    def test_empty_headers_returns_empty(self) -> None:
        result = redact_sensitive_headers({})
        self.assertEqual(result, {})

    def test_returns_new_dict(self) -> None:
        headers = {"Authorization": "secret"}
        result = redact_sensitive_headers(headers)
        self.assertIsNot(result, headers)
        self.assertEqual(headers["Authorization"], "secret")

    def test_case_insensitive_matching(self) -> None:
        headers = {"authorization": "secret", "COOKIE": "value"}
        result = redact_sensitive_headers(headers)
        self.assertEqual(result["authorization"], "[REDACTED]")
        self.assertEqual(result["COOKIE"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()

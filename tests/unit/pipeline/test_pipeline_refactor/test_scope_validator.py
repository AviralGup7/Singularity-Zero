import pytest

from src.core.middleware import (
    OutboundRequestInterceptor,
    ScopeCheckResult,
    ScopeValidator,
    ScopeViolationError,
    create_scope_guard,
    validate_url_scope,
)


class TestScopeValidator:
    """Tests for ScopeValidator and related middleware components."""

    def test_exact_hostname_match(self, scope_validator: ScopeValidator) -> None:
        """Exact hostname match is allowed."""
        result = scope_validator.check("https://example.com/page")
        assert result.allowed is True
        assert "Exact match" in result.reason

    def test_wildcard_subdomain_match(self, scope_validator: ScopeValidator) -> None:
        """Wildcard subdomain *.api.example.com matches api.example.com."""
        result = scope_validator.check("https://api.example.com/v1")
        assert result.allowed is True
        assert "Wildcard match" in result.reason

    def test_wildcard_subdomain_match_nested(self, scope_validator: ScopeValidator) -> None:
        """Wildcard subdomain *.api.example.com matches v2.api.example.com."""
        result = scope_validator.check("https://v2.api.example.com/v1")
        assert result.allowed is True

    def test_implicit_subdomain_match(self, scope_validator: ScopeValidator) -> None:
        """example.com implicitly matches www.example.com."""
        result = scope_validator.check("https://www.example.com/page")
        assert result.allowed is True
        assert "Implicit subdomain" in result.reason

    def test_sensitive_subdomain_is_excluded_unless_explicitly_scoped(self) -> None:
        """Sensitive host labels are not admitted by broad wildcard or parent scope."""
        validator = ScopeValidator({"example.com", "*.example.com"})
        result = validator.check("https://vault.example.com/secrets")
        assert result.allowed is False
        assert "Sensitive internal hostname" in result.reason

        explicit = ScopeValidator({"example.com", "vault.example.com"})
        assert explicit.check("https://vault.example.com/secrets").allowed is True

    def test_ip_exact_match(self, scope_validator: ScopeValidator) -> None:
        """Exact IP address match is allowed."""
        result = scope_validator.check("http://10.0.0.1/admin")
        assert result.allowed is True
        assert "Exact match" in result.reason

    def test_cidr_range_match(self, scope_validator: ScopeValidator) -> None:
        """CIDR range 192.168.1.0/24 matches 192.168.1.50."""
        result = scope_validator.check("http://192.168.1.50/api")
        assert result.allowed is True
        assert "CIDR range" in result.reason

    def test_out_of_scope_rejection(self, scope_validator: ScopeValidator) -> None:
        """Out-of-scope host is rejected."""
        result = scope_validator.check("https://evil.com/page")
        assert result.allowed is False
        assert result.matched_rule is None
        assert "not within the defined scope" in result.reason

    def test_url_with_path_and_query(self, scope_validator: ScopeValidator) -> None:
        """URL with path and query params is validated by hostname."""
        result = scope_validator.check("https://example.com/search?q=test&page=1&limit=10")
        assert result.allowed is True

    def test_case_insensitive_matching(self, scope_validator: ScopeValidator) -> None:
        """Hostname matching is case-insensitive."""
        result = scope_validator.check("https://EXAMPLE.COM/page")
        assert result.allowed is True

    def test_add_scope_dynamically(self, scope_validator: ScopeValidator) -> None:
        """add_scope adds a new host to the validator."""
        # Use a host not implicitly matched by example.com
        assert not scope_validator.check_hostname("totally-different.com").allowed
        scope_validator.add_scope("totally-different.com")
        result = scope_validator.check_hostname("totally-different.com")
        assert result.allowed is True

    def test_remove_scope_dynamically(self, scope_validator: ScopeValidator) -> None:
        """remove_scope removes a host from the validator."""
        assert scope_validator.check_hostname("example.com").allowed
        scope_validator.remove_scope("example.com")
        # After removal, implicit subdomain match is gone
        result = scope_validator.check_hostname("example.com")
        assert result.allowed is False

    def test_get_scope_rules(self, scope_validator: ScopeValidator) -> None:
        """get_scope_rules returns rules added via add_scope."""
        # Initial hosts added in __init__ are not in _rules list
        # Only hosts added via add_scope appear in get_scope_rules
        scope_validator.add_scope("dynamic.example.com")
        rules = scope_validator.get_scope_rules()
        assert isinstance(rules, list)
        assert "dynamic.example.com" in rules

    def test_check_hostname_standalone(self, scope_validator: ScopeValidator) -> None:
        """check_hostname validates hostnames without full URLs."""
        result = scope_validator.check_hostname("example.com")
        assert result.allowed is True
        assert result.hostname == "example.com"

    def test_check_hostname_out_of_scope(self, scope_validator: ScopeValidator) -> None:
        """check_hostname rejects out-of-scope hostnames."""
        result = scope_validator.check_hostname("evil.com")
        assert result.allowed is False

    def test_check_ip_standalone(self, scope_validator: ScopeValidator) -> None:
        """check_ip validates IP addresses."""
        result = scope_validator.check_ip("192.168.1.100")
        assert result.allowed is True
        assert result.ip_address == "192.168.1.100"

    def test_check_ip_out_of_scope(self, scope_validator: ScopeValidator) -> None:
        """check_ip rejects out-of-scope IPs."""
        result = scope_validator.check_ip("172.16.0.1")
        assert result.allowed is False

    def test_check_ip_invalid(self, scope_validator: ScopeValidator) -> None:
        """check_ip handles invalid IP addresses."""
        result = scope_validator.check_ip("not-an-ip")
        assert result.allowed is False
        assert "Invalid IP address" in result.reason

    def test_invalid_url_handling(self, scope_validator: ScopeValidator) -> None:
        """Invalid URLs are rejected gracefully."""
        result = scope_validator.check("not-a-valid-url")
        assert result.allowed is False

    def test_empty_scope_hosts_behavior(self) -> None:
        """Validator with empty scope rejects everything."""
        validator = ScopeValidator(set())
        result = validator.check("https://example.com")
        assert result.allowed is False

    def test_scope_check_result_dataclass_fields(self) -> None:
        """ScopeCheckResult has all expected fields."""
        result = ScopeCheckResult(
            allowed=True,
            reason="test",
            matched_rule="example.com",
            url="https://example.com",
            hostname="example.com",
            ip_address="1.2.3.4",
        )
        assert result.allowed is True
        assert result.reason == "test"
        assert result.matched_rule == "example.com"
        assert result.url == "https://example.com"
        assert result.hostname == "example.com"
        assert result.ip_address == "1.2.3.4"

    def test_scope_violation_error_attributes(self) -> None:
        """ScopeViolationError has correct attributes and message."""
        error = ScopeViolationError(
            target_url="https://evil.com",
            reason="Out of scope",
            scope_hosts={"example.com"},
        )
        assert error.target_url == "https://evil.com"
        assert error.reason == "Out of scope"
        assert error.scope_hosts == frozenset({"example.com"})
        assert "Scope violation" in str(error)
        assert "https://evil.com" in str(error)

    def test_validate_url_scope_convenience(self) -> None:
        """validate_url_scope is a convenience function."""
        result = validate_url_scope(
            "https://api.example.com/v1",
            {"example.com", "*.example.com"},
        )
        assert result.allowed is True

    def test_validate_url_scope_out_of_scope(self) -> None:
        """validate_url_scope rejects out-of-scope URLs."""
        result = validate_url_scope(
            "https://evil.com",
            {"example.com"},
        )
        assert result.allowed is False

    def test_create_scope_guard_decorator_factory(self) -> None:
        """create_scope_guard returns a decorator that guards functions."""
        guard = create_scope_guard({"example.com"})

        @guard
        def safe_request(method: str, url: str, **kwargs: str) -> tuple[str, str]:
            return method, url

        method, url = safe_request("GET", "https://example.com/api")
        assert method == "GET"
        assert url == "https://example.com/api"

    def test_create_scope_guard_blocks_out_of_scope(self) -> None:
        """create_scope_guard decorator raises for out-of-scope URLs."""
        guard = create_scope_guard({"example.com"})

        @guard
        def safe_request(method: str, url: str, **kwargs: str) -> tuple[str, str]:
            return method, url

        with pytest.raises(ScopeViolationError):
            safe_request("GET", "https://evil.com")

    def test_outbound_request_interceptor_allowed(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor.intercept returns method/url for allowed."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        method, url = interceptor.intercept("GET", "https://example.com/api")
        assert method == "GET"
        assert url == "https://example.com/api"

    def test_outbound_request_interceptor_blocked(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor.intercept raises for blocked URLs."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        with pytest.raises(ScopeViolationError):
            interceptor.intercept("POST", "https://evil.com/hack")

    def test_outbound_request_interceptor_audit_log(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor maintains an audit log."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        interceptor.intercept("GET", "https://example.com")
        try:
            interceptor.intercept("GET", "https://evil.com")
        except ScopeViolationError:
            pass

        log = interceptor.audit_log
        assert len(log) == 2
        assert log[0]["allowed"] is True
        assert log[1]["allowed"] is False
        assert "timestamp" in log[0]
        assert "method" in log[0]
        assert "url" in log[0]

    def test_outbound_request_interceptor_counts(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor tracks blocked/allowed counts."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        interceptor.intercept("GET", "https://example.com/1")
        interceptor.intercept("GET", "https://example.com/2")
        try:
            interceptor.intercept("GET", "https://evil.com")
        except ScopeViolationError:
            pass

        assert interceptor.allowed_count == 2
        assert interceptor.blocked_count == 1

    def test_outbound_request_interceptor_callable(self, scope_validator: ScopeValidator) -> None:
        """OutboundRequestInterceptor is callable."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        method, url = interceptor("GET", "https://example.com")
        assert method == "GET"

    def test_outbound_request_interceptor_audit_log_is_copy(
        self, scope_validator: ScopeValidator
    ) -> None:
        """audit_log returns a copy, not the internal list."""
        interceptor = OutboundRequestInterceptor(scope_validator)
        interceptor.intercept("GET", "https://example.com")
        log1 = interceptor.audit_log
        log2 = interceptor.audit_log
        assert log1 is not log2

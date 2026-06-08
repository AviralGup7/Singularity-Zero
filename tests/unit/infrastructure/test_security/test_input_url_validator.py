import os
import sys

from src.infrastructure.security.input_validation import (
    URLValidator,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestURLValidator(SecurityTestBase):
    def test_valid_url(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("https://example.com/api")
        assert result.is_valid is True

    def test_empty_url(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("")
        assert result.is_valid is False

    def test_ssrf_localhost(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("http://localhost/admin")
        assert result.is_valid is False

    def test_internal_ip(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("http://192.168.1.1/admin")
        assert result.is_valid is False

    def test_allow_internal(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("http://192.168.1.1/admin", allow_internal=True)
        assert result.is_valid is True

    def test_invalid_scheme(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("ftp://example.com/file")
        assert result.is_valid is False

    def test_validate_redirect_url_valid(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate_redirect_url("/dashboard", allowed_hosts={"example.com"})
        assert result.is_valid is True

    def test_validate_redirect_url_disallowed(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate_redirect_url("http://evil.com", allowed_hosts={"example.com"})
        assert result.is_valid is False

    def test_validate_redirect_protocol_relative(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate_redirect_url("//evil.com")
        assert result.is_valid is False

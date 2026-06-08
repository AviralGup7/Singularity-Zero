import os
import sys

from src.infrastructure.security.input_validation import (
    InputValidator,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestInputValidator(SecurityTestBase):
    def test_sanitize_string(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.sanitize_string("hello\x00world")
        assert "\x00" not in result

    def test_sanitize_dict(self) -> None:
        validator = InputValidator(self.security_config)
        data = {"key": "value\x00", "nested": {"a": "b"}}
        result = validator.sanitize_dict(data)
        assert "\x00" not in result["key"]

    def test_check_request_size(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.check_request_size(100)
        assert result.is_valid is True

    def test_check_request_size_too_large(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.check_request_size(100 * 1024 * 1024)
        assert result.is_valid is False

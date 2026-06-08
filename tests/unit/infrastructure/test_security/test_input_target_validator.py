import os
import sys

from src.infrastructure.security.input_validation import (
    TargetNameValidator,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestTargetNameValidator(SecurityTestBase):
    def test_valid_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("my-target-01")
        assert result.is_valid is True

    def test_empty_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("")
        assert result.is_valid is False

    def test_path_traversal(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("../etc/passwd")
        assert result.is_valid is False

    def test_starts_with_dot(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate(".hidden")
        assert result.is_valid is False

    def test_reserved_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("con")
        assert result.is_valid is False

    def test_sanitize_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        sanitized = validator._sanitize_name("my   target___name")
        assert sanitized == "my-target-name"

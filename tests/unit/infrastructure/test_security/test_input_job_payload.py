import os
import sys

from src.infrastructure.security.input_validation import (
    JobPayloadValidator,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase


class TestJobPayloadValidator(SecurityTestBase):
    def test_valid_payload(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            target_name="test-target",
            mode="idor",
        )
        assert result.is_valid is True

    def test_invalid_mode(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            mode="invalid_mode",
        )
        assert result.is_valid is False

    def test_invalid_modules(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            modules=["valid", "invalid module!"],
        )
        assert result.is_valid is False

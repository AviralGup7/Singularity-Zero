import unittest

from src.infrastructure.security.input_validation import (
    ValidationResult,
)


class TestValidationResult(unittest.TestCase):
    def test_defaults(self) -> None:
        result = ValidationResult()
        assert result.is_valid is True
        assert result.error_message == ""

    def test_with_errors(self) -> None:
        result = ValidationResult(valid=False, errors=["error1", "error2"])
        assert result.is_valid is False
        assert "error1" in result.error_message

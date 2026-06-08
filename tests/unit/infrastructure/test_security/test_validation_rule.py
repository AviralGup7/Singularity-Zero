import unittest

from src.infrastructure.security.input_validation import (
    ValidationRule,
)


class TestValidationRule(unittest.TestCase):
    def test_rule_creation(self) -> None:
        rule = ValidationRule(
            name="no_sql_injection",
            pattern=r"(?i)union\s+select",
            error_message="SQL injection detected",
        )
        assert rule.name == "no_sql_injection"
        assert rule.is_blocklist is True

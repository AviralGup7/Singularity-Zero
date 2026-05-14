import unittest

from src.execution.validators import ValidationStatus, validate_target
from src.execution.validators.engine import build_validator_registry
from src.execution.validators.interfaces import Validator
from src.execution.validators.strategy import ValidationStrategy
from src.execution.validators.validators import VALIDATOR_REGISTRY


class ValidationLayerInterfaceTests(unittest.TestCase):
    def test_validator_registry_entries_implement_validator_protocol(self) -> None:
        for validator in VALIDATOR_REGISTRY.values():
            self.assertIsInstance(validator, Validator)

    def test_ssrf_validator_returns_structured_result(self) -> None:
        result = validate_target(
            {
                "url": "https://app.example.com/fetch?url=http://169.254.169.254",
                "score": 8,
                "signals": ["internal_host_reference:url"],
                "parameters": ["url"],
            },
            {"callback_context": {"validation_state": "passive_only"}},
            validator_name="ssrf",
        )
        self.assertIn(result.status, {status.value for status in ValidationStatus})
        self.assertEqual(result.validator, "ssrf")
        self.assertEqual(result.category, "ssrf")

    def test_unknown_validator_raises(self) -> None:
        with self.assertRaises(ValueError):
            validate_target({}, {}, validator_name="unknown")

    def test_blackbox_registry_uses_strategy_interface(self) -> None:
        registry = build_validator_registry()
        self.assertGreaterEqual(len(registry), 4)
        for spec in registry.values():
            strategy = spec.strategy_factory()
            self.assertIsInstance(strategy, ValidationStrategy)


if __name__ == "__main__":
    unittest.main()

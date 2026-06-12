import unittest

from src.execution.validators import ValidationStatus, validate_target
from src.execution.validators.engine import build_validator_registry
from src.execution.validators.interfaces import Validator
from src.execution.validators.strategy import ValidationStrategy
from src.execution.validators.validators.registry_builder import VALIDATOR_REGISTRY


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
        for key, spec in registry.items():
            self.assertTrue(callable(spec.strategy_factory), f"{key} strategy_factory not callable")
            self.assertIsInstance(spec.name, str)
            self.assertIsInstance(spec.result_key, str)

    def test_dynamic_validation_strategy_adapter(self) -> None:
        from unittest.mock import MagicMock

        from src.execution.validators.engine._base import ValidationContext
        from src.execution.validators.engine._runner import DynamicValidationStrategy

        def mock_sandbox_callable(payload: dict) -> dict:
            return {"ok": True, "url": payload["target"]["url"]}

        strategy = DynamicValidationStrategy(
            name="demo_dynamic_check",
            result_key="demo_dynamic_check_validation",
            sandbox_callable=mock_sandbox_callable,
        )

        self.assertEqual(strategy.name, "demo_dynamic_check")
        self.assertEqual(strategy.result_key, "demo_dynamic_check_validation")

        context = ValidationContext(
            analysis_results={
                "idor": [{"url": "https://example.com/api/v1", "confidence": 0.8, "score": 8}]
            },
            ranked_priority_urls=[],
            callback_context={},
            token_replay={},
            runtime_inputs={},
            scope_hosts={"example.com"},
            http_client=MagicMock(),
            active_probe_enabled=True,
            per_validator_limit=10,
            selector_config={},
        )

        findings, errors = strategy.run(context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(errors), 0)
        self.assertEqual(findings[0]["url"], "https://example.com/api/v1")
        self.assertEqual(findings[0]["score"], 8)
        self.assertEqual(findings[0]["validator"], "demo_dynamic_check")

    def test_ssrf_validator_custom_config(self) -> None:
        # Verify custom params and internal prefixes are respected in SSRF validation
        target = {
            "url": "https://app.example.com/fetch?custom_sink=http://192.168.1.1",
            "score": 8,
            "signals": ["custom_signal"],
            "parameters": ["custom_sink"],
            "param_values": {"custom_sink": "http://192.168.1.1"},
        }
        context = {
            "callback_context": {"validation_state": "passive_only"},
            "selector_config": {
                "ssrf": {"strong_params": ["custom_sink"], "internal_prefixes": ["192.168."]}
            },
        }
        result = validate_target(target, context, validator_name="ssrf")
        self.assertEqual(result.validator, "ssrf")
        # Ensure it recognized the custom param and evaluated the internal IP correctly
        evidence = result.evidence or {}
        risk_assessments = evidence.get("risk_assessments", [])
        self.assertTrue(
            any(
                r["parameter"] == "custom_sink" and r["risk_level"] == "strong_sink"
                for r in risk_assessments
            )
        )

    def test_token_reuse_masking(self) -> None:
        # Verify tokens are masked when executing validation
        target = {"url": "https://app.example.com/api"}
        context = {
            "analysis_results": {
                "token_leak_detector": [
                    {
                        "url": "https://app.example.com/api",
                        "token_value": "secret_token_123456",
                        "location": "header",
                    }
                ]
            }
        }
        result = validate_target(target, context, validator_name="token_reuse")
        self.assertEqual(result.validator, "token_reuse")
        evidence = result.evidence or {}
        # Ensure masked_token is in the evidence and correctly obfuscated
        masked = evidence.get("masked_token", "")
        self.assertTrue(masked.startswith("secr"))
        self.assertTrue(masked.endswith("3456"))
        self.assertNotIn("secret_token_123456", str(evidence))


if __name__ == "__main__":
    unittest.main()

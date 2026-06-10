"""Tests for R1 (registry unification) and R2 (scope enforcement) and Bug G (cache key)."""

import unittest
from unittest.mock import patch

from src.execution.validators.config import (
    ScopePolicy,
    load_validation_config,
)
from src.execution.validators.engine import (
    build_validator_registry,
    run_blackbox_validation_engine,
)
from src.execution.validators.engine._base import BaseValidator, ValidationContext
from src.execution.validators.engine._http_client import (
    ValidationHttpClient,
    ValidationHttpConfig,
    _cache_key_for,
)
from src.execution.validators.engine._runner import DynamicValidationStrategy
from src.execution.validators.registry import VALIDATOR_ORDER, VALIDATOR_RESULT_KEYS
from src.execution.validators.validators import registry_builder
from src.pipeline.retry import RetryPolicy


def _make_context(**overrides: object) -> ValidationContext:
    config = ValidationHttpConfig(
        timeout_seconds=5,
        max_response_bytes=10000,
        retry_policy=RetryPolicy(max_attempts=1, initial_backoff_seconds=0.0),
    )
    defaults: dict[str, object] = {
        "analysis_results": {},
        "ranked_priority_urls": [],
        "callback_context": {},
        "token_replay": {},
        "runtime_inputs": {},
        "scope_hosts": set(),
        "http_client": ValidationHttpClient(config),
        "active_probe_enabled": False,
        "per_validator_limit": 5,
        "selector_config": {},
    }
    defaults.update(overrides)
    return ValidationContext(**defaults)  # type: ignore[arg-type]


class TestR1RegistryUnification(unittest.TestCase):
    def test_facade_registry_includes_new_validators(self) -> None:
        for name in (
            "cors",
            "jwt_weakness",
            "cache_poisoning",
            "graphql_abuse",
            "race_condition",
        ):
            self.assertIn(name, registry_builder.VALIDATOR_REGISTRY)

    def test_engine_registry_matches_facade(self) -> None:
        engine = set(build_validator_registry().keys())
        facade = set(registry_builder.VALIDATOR_REGISTRY.keys())
        # Engine registry can be a superset (sandbox validators) but must
        # contain all facade entries.
        self.assertTrue(facade.issubset(engine))

    def test_order_contains_new_validators(self) -> None:
        for name in (
            "cors",
            "graphql_abuse",
            "jwt_weakness",
            "race_condition",
            "cache_poisoning",
        ):
            self.assertIn(name, VALIDATOR_ORDER)

    def test_result_keys_contain_new_validators(self) -> None:
        for name, key in (
            ("cors", "cors_validation"),
            ("graphql_abuse", "graphql_validation"),
            ("jwt_weakness", "jwt_validation"),
            ("race_condition", "race_condition_validation"),
            ("cache_poisoning", "cache_poisoning_validation"),
        ):
            self.assertEqual(VALIDATOR_RESULT_KEYS[name], key)


class TestR2ScopeEnforcement(unittest.TestCase):
    def test_in_scope_for_returns_false_when_unscoped(self) -> None:
        ctx = _make_context(scope_hosts=set())
        self.assertFalse(ctx.in_scope_for("https://example.com/api"))

    def test_in_scope_for_returns_true_when_in_scope(self) -> None:
        ctx = _make_context(scope_hosts={"example.com"})
        self.assertTrue(ctx.in_scope_for("https://example.com/api"))

    def test_in_scope_for_returns_false_when_host_mismatch(self) -> None:
        ctx = _make_context(scope_hosts={"allowed.com"})
        self.assertFalse(ctx.in_scope_for("https://example.com/api"))

    def test_dynamic_strategy_skips_when_unscoped(self) -> None:
        def sandbox(payload: dict[str, object]) -> dict[str, object]:
            return {"ok": True, "url": str(payload.get("target", {}).get("url", ""))}

        strategy = DynamicValidationStrategy("test", "test_validation", sandbox)
        ctx = _make_context(
            scope_hosts=set(),
            scope_policy=ScopePolicy(block_active_when_unscoped=True),
            runtime_inputs={"urls": ["https://example.com"]},
        )
        with self.assertLogs("src.execution.validators.engine._runner", level="WARNING"):
            findings, errors = strategy.run(ctx)
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])

    def test_dynamic_strategy_marks_out_of_scope(self) -> None:
        def sandbox(payload: dict[str, object]) -> dict[str, object]:
            return {"ok": True, "url": str(payload.get("target", {}).get("url", ""))}

        strategy = DynamicValidationStrategy("test", "test_validation", sandbox)
        ctx = _make_context(
            scope_hosts={"allowed.com"},
            runtime_inputs={"urls": ["https://example.com"]},
        )
        findings, _errors = strategy.run(ctx)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0]["in_scope"])
        self.assertIn(
            findings[0]["scope_reason"], ("outside_scope", "host_mismatch", "out_of_scope")
        )

    def test_engine_run_with_unscoped_warns(self) -> None:
        result = run_blackbox_validation_engine(
            analysis_results={},
            ranked_priority_urls=[],
            callback_context={},
            token_replay={},
            validation_settings={
                "blackbox_validation": {
                    "enabled_validators": ["cors"],
                    "active_probe_enabled": False,
                }
            },
            runtime_inputs={},
        )
        self.assertEqual(result["settings"]["scope_hosts_count"], 0)


class TestR2BaseFindingUnscoped(unittest.TestCase):
    def test_base_finding_marks_out_of_scope_when_unscoped(self) -> None:
        class _Stub(BaseValidator):
            name = "stub"
            result_key = "stub_validation"
            category = "stub"

        validator = _Stub()
        ctx = _make_context(
            scope_hosts=set(),
            scope_policy=ScopePolicy(treat_unscoped_as_out_of_scope=True),
        )
        finding = validator._base_finding(
            url="https://example.com",
            context=ctx,
            confidence=0.5,
            validation_state="passive_only",
            signals=[],
        )
        self.assertFalse(finding["in_scope"])
        self.assertEqual(finding["scope_reason"], "scope_unavailable")


class TestBugGCacheKeyIncludesAuthHeaders(unittest.TestCase):
    def test_cache_key_differs_for_different_authorization(self) -> None:
        key1 = _cache_key_for("GET", "https://example.com", {"Authorization": "Bearer A"}, None)
        key2 = _cache_key_for("GET", "https://example.com", {"Authorization": "Bearer B"}, None)
        self.assertNotEqual(key1, key2)

    def test_cache_key_differs_for_different_cookie(self) -> None:
        key1 = _cache_key_for("GET", "https://example.com", {"Cookie": "session=abc"}, None)
        key2 = _cache_key_for("GET", "https://example.com", {"Cookie": "session=xyz"}, None)
        self.assertNotEqual(key1, key2)

    def test_cache_key_ignores_non_auth_headers(self) -> None:
        key1 = _cache_key_for("GET", "https://example.com", {"X-Forwarded-Host": "a"}, None)
        key2 = _cache_key_for("GET", "https://example.com", {"X-Forwarded-Host": "b"}, None)
        self.assertEqual(key1, key2)

    def test_cache_key_includes_body_fingerprint(self) -> None:
        key1 = _cache_key_for("POST", "https://example.com", None, "a")
        key2 = _cache_key_for("POST", "https://example.com", None, "b")
        self.assertNotEqual(key1, key2)


class TestHttpClientBodySupport(unittest.TestCase):
    def test_request_accepts_body(self) -> None:
        client = ValidationHttpClient(
            ValidationHttpConfig(
                timeout_seconds=5,
                max_response_bytes=10000,
                retry_policy=RetryPolicy(max_attempts=1, initial_backoff_seconds=0.0),
            )
        )
        with patch.object(
            __import__(
                "src.execution.validators.engine._http_client",
                fromlist=["fetch_response"],
            ),
            "fetch_response",
            return_value={
                "status_code": 200,
                "body_text": "ok",
                "headers": {"content-type": "text/plain"},
                "url": "https://example.com",
                "requested_url": "https://example.com",
                "body_length": 2,
                "redirect_count": 0,
            },
        ):
            result = client.request("https://example.com", method="POST", body="hi")
        self.assertTrue(result["ok"])
        self.assertEqual(result["status_code"], 200)


class TestR2ScopePolicyLoad(unittest.TestCase):
    def test_scope_policy_loaded_from_settings(self) -> None:
        cfg = load_validation_config(
            {
                "extensions": {
                    "blackbox_validation": {
                        "scope": {
                            "block_active_when_unscoped": False,
                            "treat_unscoped_as_out_of_scope": False,
                        }
                    }
                }
            }
        )
        self.assertFalse(cfg.scope_policy.block_active_when_unscoped)
        self.assertFalse(cfg.scope_policy.treat_unscoped_as_out_of_scope)


if __name__ == "__main__":
    unittest.main()

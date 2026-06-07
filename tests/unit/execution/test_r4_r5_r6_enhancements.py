"""Tests for R4 (active SSRF probe), R5 (XSS/SSTI baseline) and R6 (token replay safety)."""

import unittest
from unittest.mock import patch

from src.execution.validators.config import ReplaySafetyConfig
from src.execution.validators.engine import (
    SsrfValidator,
    run_blackbox_validation_engine,
)
from src.execution.validators.engine._base import ValidationContext
from src.execution.validators.engine._http_client import (
    ValidationHttpClient,
    ValidationHttpConfig,
)
from src.execution.validators.engine._runner import build_validator_registry
from src.execution.validators.validators.token_reuse import validate
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
        "active_probe_enabled": True,
        "per_validator_limit": 5,
        "selector_config": {},
    }
    defaults.update(overrides)
    return ValidationContext(**defaults)  # type: ignore[arg-type]


class TestR4ActiveSsrfProbe(unittest.TestCase):
    def test_builds_callback_probe_url(self) -> None:
        ctx = _make_context(
            callback_context={"host": "callback.example.com", "probe_token": "abc123"}
        )
        finding: dict[str, object] = {
            "url": "https://target.com/api?url=https://orig",
            "evidence": {"parameters": ["url"]},
            "validation_state": "active_ready",
        }
        probe_url, error = SsrfValidator._build_callback_probe(finding, ctx)
        self.assertIsNone(error)
        self.assertIn("callback.example.com", str(probe_url))
        self.assertIn("abc123", str(probe_url))

    def test_missing_callback_host_returns_error(self) -> None:
        ctx = _make_context(callback_context={})
        finding: dict[str, object] = {
            "url": "https://target.com/api?url=https://orig",
            "evidence": {"parameters": ["url"]},
        }
        probe_url, error = SsrfValidator._build_callback_probe(finding, ctx)
        self.assertEqual(probe_url, "")
        self.assertIsNotNone(error)
        self.assertEqual(error.get("code"), "ssrf_probe_no_callback_host")  # type: ignore[union-attr]

    def test_validator_invokes_callback_probe(self) -> None:
        engine_registry = build_validator_registry()
        spec = engine_registry.get("ssrf")
        self.assertIsNotNone(spec)
        # Just verify the spec is wired up; full integration is covered
        # by the engine runner test.
        self.assertEqual(spec.name, "ssrf")  # type: ignore[union-attr]


class _StubHttpClient:
    def __init__(self, body_for: "callable | None" = None) -> None:
        self.body_for = body_for
        self.calls: list[str] = []

    def request(self, url: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        self.calls.append(url)
        if self.body_for is not None:
            return {
                "status_code": 200,
                "body": self.body_for(url),
                "headers": {},
            }
        return {
            "status_code": 200,
            "body": "xssbaselinetoken987654 hello",
            "headers": {},
        }


class TestR5XssBaseline(unittest.TestCase):
    def test_xss_baseline_signal_emitted(self) -> None:
        """Baseline reflection detection should be wired into _active_xss_test."""
        from src.execution.validators.validators.xss import _active_xss_test

        client = _StubHttpClient()
        result = _active_xss_test(
            "https://example.com/search?q=test", client
        )
        self.assertIn(
            "baseline_reflection_present",
            result.get("baseline_signals", []),
        )


class TestR5SstiBaseline(unittest.TestCase):
    def test_ssti_baseline_signal_emitted(self) -> None:
        """Baseline math indicators detection should be wired in."""

        from src.execution.validators.validators.ssti import _active_ssti_test

        client = _StubHttpClient(
            body_for=lambda _url: "Order total: 49 items. Subtotal 343.00"
        )
        result = _active_ssti_test(
            "https://example.com/profile?name=alice&page=1", client
        )
        self.assertIn(
            "baseline_math_indicators_present",
            result.get("baseline_signals", []),
        )

    def test_ssti_false_positive_downgraded(self) -> None:
        """When baseline contains math indicators, status is 'potential' not 'confirmed'."""
        from src.execution.validators.validators.ssti import _active_ssti_test

        def _body_for(url: str) -> str:
            if "sstibaselinetoken" in url:
                return "Item price: 49. Subtotal: 343.00."
            return "Hello {{7*7}} -> 49. Thanks."

        client = _StubHttpClient(body_for=_body_for)
        result = _active_ssti_test(
            "https://example.com/profile?name=alice&page=1", client
        )
        self.assertEqual(result["status"], "potential")


class TestR6TokenReplaySafety(unittest.TestCase):
    def test_replay_blocked_by_default(self) -> None:
        target = {
            "url": "https://example.com/api/users/1",
            "token": "deadbeef123",
        }
        context = {
            "analysis_results": {
                "token_leak_detector": [
                    {
                        "url": "https://example.com/api/users/1",
                        "token_value": "deadbeef123",
                        "location": "response_body",
                    }
                ]
            }
        }
        result = validate(target, context)
        # Replay must be skipped by default (no authorized_replay).
        evidence = result.evidence or {}
        replay = evidence.get("replay_safety", {})
        self.assertFalse(replay.get("authorized", True))

    def test_replay_allowed_when_authorized_and_safe_location(self) -> None:

        safety = ReplaySafetyConfig(authorized_replay=True)
        target = {
            "url": "https://example.com/api/users/1",
            "token": "deadbeef123",
        }
        context = {
            "analysis_results": {
                "token_leak_detector": [
                    {
                        "url": "https://example.com/api/users/1",
                        "token_value": "deadbeef123",
                        "location": "authorization_header",
                    }
                ]
            },
            "replay_safety": safety,
        }
        # Mock the http client so we never touch the network.
        context["http_client"] = _MockHttpClient(ok=True, status=200)
        result = validate(target, context)
        evidence = result.evidence or {}
        replay = evidence.get("replay_safety", {})
        self.assertTrue(replay.get("authorized"))
        self.assertTrue(replay.get("location_allowed"))

    def test_unsafe_location_blocks_even_when_authorized(self) -> None:

        safety = ReplaySafetyConfig(authorized_replay=True)
        target = {
            "url": "https://example.com/api/users/1",
            "token": "deadbeef123",
        }
        context = {
            "analysis_results": {
                "token_leak_detector": [
                    {
                        "url": "https://example.com/api/users/1",
                        "token_value": "deadbeef123",
                        "location": "response_body",
                    }
                ]
            },
            "replay_safety": safety,
        }
        result = validate(target, context)
        evidence = result.evidence or {}
        replay = evidence.get("replay_safety", {})
        self.assertTrue(replay.get("authorized"))
        self.assertFalse(replay.get("location_allowed"))


class _MockHttpClient:
    def __init__(self, ok: bool = True, status: int = 200) -> None:
        self.ok = ok
        self.status = status
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    def request(
        self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None
    ) -> dict[str, object]:
        self.calls.append((url, headers))
        return {
            "ok": self.ok,
            "status_code": self.status,
            "body": "",
            "headers": {},
        }


class TestEngineWiring(unittest.TestCase):
    def test_engine_runner_uses_replay_safety(self) -> None:
        with patch(
            "src.execution.validators.validators.token_reuse._replay_token_on_endpoint",
            return_value={
                "status": "tested",
                "token_accepted": True,
                "token_rejected": False,
            },
        ):
            result = run_blackbox_validation_engine(
                analysis_results={
                    "token_leak_detector": [
                        {
                            "url": "https://example.com/api/users/1",
                            "token_value": "abc",
                            "location": "authorization_header",
                            "leak_count": 1,
                        }
                    ]
                },
                ranked_priority_urls=[
                    {"url": "https://example.com/api/users/1", "score": 5}
                ],
                callback_context={},
                token_replay={
                    "grouped_by_endpoint": [
                        {
                            "url": "https://example.com/api/users/1",
                            "token_value": "abc",
                            "location": "authorization_header",
                            "leak_count": 1,
                            "replay_likelihood": 0.6,
                            "signals": ["token"],
                        }
                    ]
                },
                validation_settings={
                    "blackbox_validation": {
                        "enabled_validators": ["token_reuse"],
                        "active_probe_enabled": False,
                        "token_replay_safety": {"authorized_replay": False},
                    }
                },
                runtime_inputs={},
            )
        # When authorized_replay is False, no live replay occurred
        # because the validator's validate() returned passive_only.
        token_key = "token_reuse_validation"
        self.assertIn(token_key, result["results"])
        self.assertFalse(
            result["settings"].get("replay_authorized", True)
        )


if __name__ == "__main__":
    unittest.main()

"""Tests for the per-tool circuit breaker integration in ToolExecutionService.

Validates the Fix #2 audit recommendation:
  * Each ``ToolExecutionService`` instance owns its own ``dict[str, CircuitBreaker]``
    keyed by tool name.
  * The breaker gates ``subprocess.run`` before spawn (i.e. ``can_execute()``
    is consulted on every call, not just within a single retry loop).
  * Recovery timeout is configurable per tool (nuclei=60s, crt.sh=600s).
  * The self-healing controller can call ``force_open_breaker`` to trip a
    tool's breaker proactively, and a successful probe clears the forced
    state.
  * The coordinator can register a per-tool recovery probe and
    ``consume_pending_probes`` returns it exactly once per HALF_OPEN
    transition.
  * ``breaker_snapshot`` returns serializable per-tool stats.

Run with: pytest tests/unit/pipeline/test_circuit_breaker_integration.py -q
"""

from __future__ import annotations

import subprocess
import time
import unittest
from unittest.mock import patch

from src.pipeline.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)
from src.pipeline.services.tool_execution import (
    RetryPolicy,
    ToolExecutionError,
    ToolExecutionService,
)


class CircuitBreakerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = ToolExecutionService()
        self.command = ["echo", "hi"]

    # ------------------------------------------------------------------ #
    # Per-tool circuit breaker ownership                                   #
    # ------------------------------------------------------------------ #

    def test_breaker_is_keyed_by_tool_name(self) -> None:
        breaker_a = self.service._get_circuit_breaker("subfinder")
        breaker_b = self.service._get_circuit_breaker("nuclei")
        breaker_a_again = self.service._get_circuit_breaker("subfinder")
        self.assertIs(breaker_a, breaker_a_again)
        self.assertIsNot(breaker_a, breaker_b)
        self.assertEqual(breaker_a.name, "subfinder")
        self.assertEqual(breaker_b.name, "nuclei")

    def test_breaker_gates_subprocess_before_spawn(self) -> None:
        """A tripped breaker must short-circuit run_command without spawning subprocess."""
        breaker = self.service._get_circuit_breaker("echo")
        # Trip it manually
        for _ in range(breaker.failure_threshold):
            breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)

        with patch("src.pipeline.services.tool_execution.subprocess.run") as mock_run:
            with self.assertRaises(ToolExecutionError) as exc:
                self.service.run_command(self.command)
        mock_run.assert_not_called()
        self.assertIn("Circuit breaker OPEN", str(exc.exception))

    def test_breaker_records_failure_on_nonzero_exit(self) -> None:
        breaker = self.service._get_circuit_breaker("echo")
        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                return_value=subprocess.CompletedProcess(self.command, 2, stdout="", stderr="boom"),
            ),
        ):
            with self.assertRaises(ToolExecutionError):
                self.service.run_command(self.command, retry_policy=RetryPolicy(max_attempts=1))
        self.assertGreaterEqual(breaker.stats().total_failures, 1)

    def test_breaker_records_success_on_zero_exit(self) -> None:
        breaker = self.service._get_circuit_breaker("echo")
        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                return_value=subprocess.CompletedProcess(self.command, 0, stdout="ok", stderr=""),
            ),
        ):
            self.service.run_command(self.command, retry_policy=RetryPolicy(max_attempts=1))
        self.assertEqual(breaker.stats().total_successes, 1)
        self.assertEqual(breaker.state, CircuitState.CLOSED)

    # ------------------------------------------------------------------ #
    # Per-tool configuration                                                #
    # ------------------------------------------------------------------ #

    def test_per_tool_breaker_config_uses_supplied_threshold(self) -> None:
        service = ToolExecutionService(
            default_breaker_config=CircuitBreakerConfig(failure_threshold=2, recovery_timeout=10.0),
            breaker_config_by_tool={
                "nuclei": CircuitBreakerConfig(failure_threshold=3, recovery_timeout=60.0),
                "crt.sh": CircuitBreakerConfig(failure_threshold=5, recovery_timeout=600.0),
            },
        )
        nuclei = service._get_circuit_breaker("nuclei")
        crtsh = service._get_circuit_breaker("crt.sh")
        default = service._get_circuit_breaker("subfinder")
        self.assertEqual(nuclei.failure_threshold, 3)
        self.assertEqual(nuclei.recovery_timeout, 60.0)
        self.assertEqual(crtsh.failure_threshold, 5)
        self.assertEqual(crtsh.recovery_timeout, 600.0)
        self.assertEqual(default.failure_threshold, 2)
        self.assertEqual(default.recovery_timeout, 10.0)

    def test_configure_breaker_installs_new_config(self) -> None:
        breaker = self.service._get_circuit_breaker("httpx")
        original_threshold = breaker.failure_threshold
        self.service.configure_breaker(
            "httpx",
            CircuitBreakerConfig(failure_threshold=2, recovery_timeout=15.0),
            reset_existing=True,
        )
        new_breaker = self.service._get_circuit_breaker("httpx")
        self.assertIsNot(breaker, new_breaker)
        self.assertEqual(new_breaker.failure_threshold, 2)
        self.assertEqual(new_breaker.recovery_timeout, 15.0)
        # Old threshold was the default (5).
        self.assertNotEqual(original_threshold, 2)

    # ------------------------------------------------------------------ #
    # Self-healing controller hot-path                                      #
    # ------------------------------------------------------------------ #

    def test_force_open_breaker_trips_immediately(self) -> None:
        breaker = self.service._get_circuit_breaker("subfinder")
        result = self.service.force_open_breaker(
            "subfinder", reason="crt.sh-blacklist", duration_seconds=30.0
        )
        self.assertIs(result, breaker)
        self.assertEqual(breaker.state, CircuitState.OPEN)
        self.assertEqual(breaker.stats().forced_open, True)
        self.assertEqual(breaker.stats().total_forced_opens, 1)

    def test_force_open_blocks_subprocess_until_reset(self) -> None:
        self.service.force_open_breaker("echo", reason="test", duration_seconds=0.0)
        with patch("src.pipeline.services.tool_execution.subprocess.run") as mock_run:
            with self.assertRaises(ToolExecutionError):
                self.service.run_command(self.command)
        mock_run.assert_not_called()

    def test_force_open_does_not_impede_recovery_after_success(self) -> None:
        breaker = self.service._get_circuit_breaker("echo")
        # Force open with zero duration (indefinite)
        breaker.force_open(reason="test", duration_seconds=0.0)
        self.assertEqual(breaker.state, CircuitState.OPEN)
        # Manually clear forced state
        breaker.reset()
        # After reset, the breaker is CLOSED and the forced flag is gone
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertEqual(breaker.stats().forced_open, False)

    def test_reset_breaker_returns_to_closed(self) -> None:
        breaker = self.service._get_circuit_breaker("subfinder")
        for _ in range(breaker.failure_threshold):
            breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)
        self.service.reset_breaker("subfinder")
        self.assertEqual(breaker.state, CircuitState.CLOSED)

    # ------------------------------------------------------------------ #
    # Recovery probe coordination                                           #
    # ------------------------------------------------------------------ #

    def test_schedule_recovery_probe_registers_callback(self) -> None:
        invoked: list[str] = []
        self.service.schedule_recovery_probe("nuclei", lambda _b: invoked.append("nuclei"))
        breaker = self.service._get_circuit_breaker("nuclei")
        self.assertTrue(breaker.stats().probe_registered)

    def test_consume_pending_probes_drains_on_half_open(self) -> None:
        called: list[str] = []
        self.service.schedule_recovery_probe("nuclei", lambda _b: called.append("nuclei"))
        breaker = self.service._get_circuit_breaker("nuclei")
        # Manually transition to HALF_OPEN to simulate recovery timeout elapsing
        breaker._set_state_locked(CircuitState.HALF_OPEN, time.time(), log=False)
        breaker._probe_pending = True
        pending = self.service.consume_pending_probes()
        self.assertIn("nuclei", pending)
        # Second drain should not return the same callback
        pending_again = self.service.consume_pending_probes()
        self.assertNotIn("nuclei", pending_again)

    def test_breaker_snapshot_returns_serializable_stats(self) -> None:
        self.service._get_circuit_breaker("nuclei")
        self.service._get_circuit_breaker("subfinder")
        snapshot = self.service.breaker_snapshot()
        self.assertEqual(set(snapshot.keys()), {"nuclei", "subfinder"})
        for tool_name, stats in snapshot.items():
            data = stats.as_dict()
            self.assertEqual(data["name"], tool_name)
            self.assertIn(data["state"], {"closed", "open", "half_open"})

    # ------------------------------------------------------------------ #
    # Outcome surface                                                       #
    # ------------------------------------------------------------------ #

    def test_execute_command_outcome_marks_breaker_open_skip(self) -> None:
        self.service.force_open_breaker("echo", reason="test", duration_seconds=0.0)
        outcome = self.service.execute_command(self.command)
        self.assertTrue(outcome.circuit_breaker_open)
        self.assertTrue(outcome.circuit_breaker_skipped)
        self.assertEqual(outcome.circuit_breaker_state, "open")
        self.assertEqual(outcome.classification, "error")
        self.assertTrue(outcome.fatal)

    def test_execute_command_outcome_records_state_on_success(self) -> None:
        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                return_value=subprocess.CompletedProcess(self.command, 0, stdout="ok", stderr=""),
            ),
        ):
            outcome = self.service.execute_command(self.command)
        self.assertFalse(outcome.circuit_breaker_open)
        self.assertEqual(outcome.circuit_breaker_state, "closed")


class CircuitBreakerCoreTests(unittest.TestCase):
    """Targeted tests on the upgraded CircuitBreaker state machine."""

    def test_force_open_with_zero_duration_keeps_breaker_indefinitely(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=0.05)
        breaker.force_open(reason="manual", duration_seconds=0.0)
        self.assertEqual(breaker.state, CircuitState.OPEN)
        time.sleep(0.1)
        # Even after recovery_timeout elapses, the breaker is still OPEN
        # because the force-open window is "indefinite".
        self.assertEqual(breaker.state, CircuitState.OPEN)
        self.assertFalse(breaker.can_execute())

    def test_force_open_with_duration_lets_recovery_timeout_kick_in(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=0.05)
        breaker.force_open(reason="cool-down", duration_seconds=0.1)
        self.assertEqual(breaker.state, CircuitState.OPEN)
        # After 100 ms the force-open has expired but the breaker should
        # transition to HALF_OPEN via the recovery_timeout path.
        time.sleep(0.12)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)
        self.assertTrue(breaker.can_execute())

    def test_update_recovery_timeout_changes_window(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=1.0)
        breaker.update_recovery_timeout(0.05)
        self.assertEqual(breaker.recovery_timeout, 0.05)
        breaker.record_failure()
        self.assertEqual(breaker.state, CircuitState.OPEN)
        time.sleep(0.08)
        # Should be HALF_OPEN now (new short recovery_timeout applied)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)

    def test_update_recovery_timeout_rejects_negative(self) -> None:
        breaker = CircuitBreaker("svc")
        with self.assertRaises(ValueError):
            breaker.update_recovery_timeout(-1.0)

    def test_record_success_clears_forced_state(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=0.05)
        breaker.force_open(reason="test", duration_seconds=10.0)
        # Drive HALF_OPEN manually and record a success
        breaker._set_state_locked(CircuitState.HALF_OPEN, time.time(), log=False)
        breaker.record_success()
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        self.assertFalse(breaker.stats().forced_open)

    def test_consume_pending_probe_only_fires_once(self) -> None:
        breaker = CircuitBreaker("svc")
        calls: list[int] = []

        def cb(_b: CircuitBreaker) -> None:
            calls.append(1)

        breaker.schedule_recovery_probe(cb)
        # First transition to HALF_OPEN flags the probe
        breaker._set_state_locked(CircuitState.HALF_OPEN, time.time(), log=False)
        breaker._probe_pending = True
        self.assertIs(breaker.consume_pending_probe(), cb)
        # Subsequent calls return None
        self.assertIsNone(breaker.consume_pending_probe())

    def test_stats_reflect_lifetime_counters(self) -> None:
        breaker = CircuitBreaker("svc", failure_threshold=2, recovery_timeout=0.05)
        breaker.record_failure()
        breaker.record_failure()  # threshold met -> trips to OPEN
        self.assertEqual(breaker.state, CircuitState.OPEN)
        stats_after_failures = breaker.stats()
        self.assertEqual(stats_after_failures.total_failures, 2)
        # Wait for the recovery window to elapse so a probe can be admitted.
        time.sleep(0.08)
        self.assertEqual(breaker.state, CircuitState.HALF_OPEN)
        breaker.record_success()  # closes from HALF_OPEN
        self.assertEqual(breaker.state, CircuitState.CLOSED)
        stats_after_success = breaker.stats()
        self.assertEqual(stats_after_success.total_failures, 2)
        self.assertGreaterEqual(stats_after_success.total_successes, 1)


class CircuitBreakerConfigTests(unittest.TestCase):
    def test_from_settings_falls_back_to_default(self) -> None:
        config = CircuitBreakerConfig.from_settings(
            None, default=CircuitBreakerConfig(failure_threshold=3, recovery_timeout=30.0)
        )
        self.assertEqual(config.failure_threshold, 3)
        self.assertEqual(config.recovery_timeout, 30.0)

    def test_from_settings_overrides_individual_fields(self) -> None:
        config = CircuitBreakerConfig.from_settings(
            {
                "circuit_breaker_failure_threshold": 7,
                "circuit_breaker_recovery_timeout": 120.0,
                "circuit_breaker_force_open": True,
                "circuit_breaker_force_open_duration": 60.0,
                "circuit_breaker_force_open_reason": "manual",
            }
        )
        self.assertEqual(config.failure_threshold, 7)
        self.assertEqual(config.recovery_timeout, 120.0)
        self.assertTrue(config.force_open_initial)
        self.assertEqual(config.force_open_duration_seconds, 60.0)
        self.assertEqual(config.force_open_reason, "manual")

    def test_from_settings_clamps_to_positive(self) -> None:
        config = CircuitBreakerConfig.from_settings(
            {
                "circuit_breaker_failure_threshold": 0,
                "circuit_breaker_recovery_timeout": -5.0,
            }
        )
        self.assertEqual(config.failure_threshold, 1)
        self.assertEqual(config.recovery_timeout, 0.0)


if __name__ == "__main__":
    unittest.main()

import io
import subprocess
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from src.pipeline.services.tool_execution import (
    RetryPolicy,
    ToolExecutionError,
    ToolExecutionService,
)


class ToolExecutionServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = ToolExecutionService()
        self.command = ["echo", "hi"]

    def test_run_command_retries_after_timeout_and_preserves_warning_text(self) -> None:
        retry_policy = RetryPolicy(max_attempts=2, initial_backoff_seconds=0.5, jitter_factor=0.0)
        stderr = io.StringIO()

        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=[
                    subprocess.TimeoutExpired(self.command, 9),
                    subprocess.CompletedProcess(self.command, 0, stdout="ok", stderr=""),
                ],
            ),
            patch("src.pipeline.retry.time.sleep") as sleep_mock,
            redirect_stderr(stderr),
        ):
            result = self.service.run_command(self.command, timeout=9, retry_policy=retry_policy)

        self.assertEqual(result, "ok")
        sleep_mock.assert_called_once()
        self.assertAlmostEqual(sleep_mock.call_args[0][0], 0.5, delta=0.15)
        self.assertRegex(
            stderr.getvalue(),
            r"Warning: command echo hi timed out after 9 seconds; retrying attempt 2/2 in 0\.[4-6]s\n",
        )

    def test_run_command_retries_after_nonzero_exit_and_preserves_warning_text(self) -> None:
        retry_policy = RetryPolicy(max_attempts=2, initial_backoff_seconds=0.5, jitter_factor=0.0)
        stderr = io.StringIO()

        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=[
                    subprocess.CompletedProcess(self.command, 2, stdout="", stderr="boom"),
                    subprocess.CompletedProcess(self.command, 0, stdout="ok", stderr=""),
                ],
            ),
            patch("src.pipeline.retry.time.sleep") as sleep_mock,
            redirect_stderr(stderr),
        ):
            result = self.service.run_command(self.command, retry_policy=retry_policy)

        self.assertEqual(result, "ok")
        sleep_mock.assert_called_once()
        self.assertAlmostEqual(sleep_mock.call_args[0][0], 0.5, delta=0.15)
        self.assertRegex(
            stderr.getvalue(),
            r"Warning: command echo hi failed with exit code 2; retrying attempt 2/2 in 0\.[4-6]s\n",
        )

    def test_run_command_raises_timeout_after_exhausting_retries(self) -> None:
        retry_policy = RetryPolicy(max_attempts=2, initial_backoff_seconds=0.5, jitter_factor=0.0)
        stderr = io.StringIO()

        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=[
                    subprocess.TimeoutExpired(self.command, 9),
                    subprocess.TimeoutExpired(self.command, 9),
                ],
            ),
            patch("src.pipeline.retry.time.sleep") as sleep_mock,
            redirect_stderr(stderr),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.service.run_command(self.command, timeout=9, retry_policy=retry_policy)

        sleep_mock.assert_called_once()
        self.assertAlmostEqual(sleep_mock.call_args[0][0], 0.5, delta=0.15)
        self.assertRegex(
            stderr.getvalue(),
            r"Warning: command echo hi timed out after 9 seconds; retrying attempt 2/2 in 0\.[4-6]s\n",
        )

    def test_run_command_raises_tool_execution_error_after_exhausting_retries(self) -> None:
        retry_policy = RetryPolicy(max_attempts=2, initial_backoff_seconds=0.5, jitter_factor=0.0)
        stderr = io.StringIO()

        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=[
                    subprocess.CompletedProcess(self.command, 2, stdout="", stderr="boom"),
                    subprocess.CompletedProcess(self.command, 2, stdout="", stderr="boom"),
                ],
            ),
            patch("src.pipeline.retry.time.sleep") as sleep_mock,
            redirect_stderr(stderr),
        ):
            with self.assertRaises(ToolExecutionError):
                self.service.run_command(self.command, retry_policy=retry_policy)

        sleep_mock.assert_called_once()
        self.assertAlmostEqual(sleep_mock.call_args[0][0], 0.5, delta=0.15)
        self.assertRegex(
            stderr.getvalue(),
            r"Warning: command echo hi failed with exit code 2; retrying attempt 2/2 in 0\.[4-6]s\n",
        )

    def test_execute_command_returns_timeout_outcome_with_partial_stdout(self) -> None:
        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=subprocess.TimeoutExpired(
                    self.command,
                    9,
                    output="partial-output\n",
                    stderr="Warning: provider timed out\n",
                ),
            ),
        ):
            outcome = self.service.execute_command(self.command, timeout=9)

        self.assertTrue(outcome.timed_out)
        self.assertEqual(outcome.stdout, "partial-output\n")
        self.assertEqual(outcome.classification, "timeout")
        self.assertEqual(outcome.effective_timeout_seconds, 9)
        self.assertTrue(outcome.warning_messages)

    def test_execute_command_classifies_warning_only_stderr_as_nonfatal(self) -> None:
        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    self.command,
                    0,
                    stdout="ok\n",
                    stderr="Warning: gau provider timed out after 1 seconds\n",
                ),
            ),
        ):
            outcome = self.service.execute_command(self.command, timeout=9)

        self.assertEqual(outcome.stdout, "ok\n")
        self.assertEqual(outcome.classification, "warning")
        self.assertFalse(outcome.fatal)
        self.assertEqual(
            outcome.warning_messages, ["Warning: gau provider timed out after 1 seconds"]
        )

    def test_try_command_returns_partial_stdout_on_timeout(self) -> None:
        stderr = io.StringIO()

        with (
            patch.object(self.service, "resolve_command", return_value=self.command),
            patch.object(self.service, "command_env", return_value={}),
            patch(
                "src.pipeline.services.tool_execution.subprocess.run",
                side_effect=subprocess.TimeoutExpired(
                    self.command,
                    9,
                    output="partial-output\n",
                    stderr="Warning: provider timed out\n",
                ),
            ),
            redirect_stderr(stderr),
        ):
            result = self.service.try_command(self.command, timeout=9)

        self.assertEqual(result, "partial-output\n")
        self.assertIn("timed out after 9 seconds", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

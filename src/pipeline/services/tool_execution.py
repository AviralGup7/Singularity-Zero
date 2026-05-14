"""Tool execution service for running external security testing tools.

Provides ToolExecutionService for resolving tool paths, executing commands
with retry support, and managing environment variables for external tools.

Also provides the canonical `run_external_tool()` function and the
`ToolInvocation` / `CompletedToolRun` contract for all external binary execution.
"""

from __future__ import annotations

import dataclasses
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from src.core.contracts.pipeline import TIMEOUT_DEFAULTS
from src.core.logging.pipeline_logging import emit_retry_warning, emit_warning
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.stderr_classification import StderrClassification, classify_stderr_lines
from src.pipeline.retry import RetryPolicy, retry_ready, sleep_before_retry

from .circuit_breaker import CircuitBreaker

logger = get_pipeline_logger(__name__)

SHELL_META = re.compile(r"[;|&$`\n\r]")

_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}

# --------------------------------------------------------------------------- #
# ToolInvocation & CompletedToolRun — canonical subprocess contract           #
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True, frozen=True)
class ToolInvocation:
    """Portable description of an external tool invocation.

    This is the ONLY interface for running external binaries in the pipeline.
    All subprocess.run / create_subprocess_exec calls must go through
    run_external_tool() so that timeout handling, stderr classification,
    and environment isolation are applied uniformly.
    """

    tool_name: str
    args: list[str] = dataclasses.field(default_factory=list)
    timeout_seconds: int | None = None
    env: dict[str, str] | None = None
    working_dir: str | Path | None = None
    stdin: str | None = None

    @property
    def command(self) -> list[str]:
        return [self.tool_name, *self.args]


@dataclasses.dataclass(slots=True)
class CompletedToolRun:
    """Structured result of an external tool invocation.

    Returned by run_external_tool().  Never raises on timeout —
    timed_out=True indicates the timeout was exceeded.
    """

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    timeout_events: list[str] = dataclasses.field(default_factory=list)
    stderr_classification: StderrClassification | None = None
    duration_seconds: float = 0.0
    tool_name: str = ""

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.exit_code == 0


def get_circuit_breaker(tool_name: str) -> CircuitBreaker:
    if tool_name not in _CIRCUIT_BREAKERS:
        _CIRCUIT_BREAKERS[tool_name] = CircuitBreaker()
    return _CIRCUIT_BREAKERS[tool_name]


class ToolExecutionError(RuntimeError):
    """Exception raised when a tool execution command fails."""

    def __init__(self, command: list[str], returncode: int, stderr: str):
        self.command = list(command)
        self.returncode = returncode
        self.stderr = stderr.strip()
        message = f"Command failed: {' '.join(command)}"
        if self.stderr:
            message = f"{message}\n{self.stderr}"
        super().__init__(message)


# --------------------------------------------------------------------------- #
# run_external_tool — unified external binary runner                           #
# --------------------------------------------------------------------------- #


async def run_external_tool(invocation: ToolInvocation) -> CompletedToolRun:
    """Run an external binary and return a structured CompletedToolRun.

    This is the single entry point for ALL external binary execution in the
    pipeline.  It wraps subprocess.run with:
      - Consistent timeout handling (never raises — returns timed_out=True)
      - Stderr classification using classify_stderr_lines()
      - Environment and working directory support
      - Duration tracking

    Args:
        invocation: ToolInvocation describing the tool, args, timeout, env, etc.

    Returns:
        CompletedToolRun with stdout, stderr, exit_code, timed_out flag,
        timeout_events list, and StderrClassification.
    """
    started = time.monotonic()
    command = invocation.command
    timeout = invocation.timeout_seconds or int(TIMEOUT_DEFAULTS["tool_command_seconds"])
    env = invocation.env
    cwd = str(invocation.working_dir) if invocation.working_dir else None

    base_env = os.environ.copy()
    if env:
        merged_env = {**base_env, **env}
    else:
        merged_env = base_env

    try:
        process = subprocess.run(
            command,
            input=invocation.stdin,
            text=True,
            encoding="utf-8",
            errors="ignore",
            capture_output=True,
            timeout=timeout,
            check=False,
            env=merged_env,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        stderr_text = _coerce_output_text(exc.stderr)
        stderr_lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
        classification = classify_stderr_lines(stderr_lines)
        duration = round(time.monotonic() - started, 3)
        return CompletedToolRun(
            stdout=_coerce_output_text(exc.stdout),
            stderr=stderr_text,
            exit_code=-1,
            timed_out=True,
            timeout_events=classification.timeout_events,
            stderr_classification=classification,
            duration_seconds=duration,
            tool_name=invocation.tool_name,
        )
    except OSError as exc:
        duration = round(time.monotonic() - started, 3)
        stderr_text = str(exc)
        stderr_lines = [stderr_text]
        classification = classify_stderr_lines(stderr_lines)
        return CompletedToolRun(
            stdout="",
            stderr=stderr_text,
            exit_code=1,
            timed_out=False,
            timeout_events=[],
            stderr_classification=classification,
            duration_seconds=duration,
            tool_name=invocation.tool_name,
        )

    stdout_text = _coerce_output_text(process.stdout)
    stderr_text = _coerce_output_text(process.stderr)
    stderr_lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    classification = classify_stderr_lines(stderr_lines)
    duration = round(time.monotonic() - started, 3)

    return CompletedToolRun(
        stdout=stdout_text,
        stderr=stderr_text,
        exit_code=process.returncode,
        timed_out=False,
        timeout_events=classification.timeout_events,
        stderr_classification=classification,
        duration_seconds=duration,
        tool_name=invocation.tool_name,
    )


def _coerce_output_text(value: str | bytes | None) -> str:
    """Coerce subprocess output to string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return value


@dataclasses.dataclass(slots=True)
class ToolExecutionOutcome:
    command: list[str]
    stdout: str = ""
    stderr_lines: list[str] = dataclasses.field(default_factory=list)
    returncode: int = 0
    timed_out: bool = False
    configured_timeout_seconds: int | None = None
    effective_timeout_seconds: int | None = None
    attempt_count: int = 1
    classification: str = "ok"
    fatal: bool = False
    warning_messages: list[str] = dataclasses.field(default_factory=list)
    error_message: str = ""
    duration_seconds: float = 0.0

    @property
    def stderr_text(self) -> str:
        return "\n".join(self.stderr_lines)


class ToolExecutionService:
    """Service for resolving and executing external security tools."""

    def search_dirs(self) -> list[Path]:
        """Return directories to search for external tool binaries.

        Includes workspace-local tools, Go bin, scoop shims, and common
        installation paths. Only specific tool directories are included
        to avoid overly broad filesystem scanning.
        """
        user_home = Path.home()
        workspace_root = Path(__file__).resolve().parents[3]
        return [
            workspace_root / ".tools" / "bin",
            workspace_root / "tools" / "bin",
            user_home / "go" / "bin",
            user_home / "scoop" / "shims",
            Path("C:/Program Files/Go/bin"),
        ]

    def candidate_paths(self, name: str) -> list[Path]:
        executable = (
            f"{name}.exe"
            if sys.platform.startswith("win") and not name.lower().endswith(".exe")
            else name
        )
        candidates = [directory / executable for directory in self.search_dirs()]
        return [path for path in candidates if path.exists()]

    def resolve_tool_path(self, name: str) -> str | None:
        for candidate in self.candidate_paths(name):
            return str(candidate)
        direct = shutil.which(name)
        if direct:
            return direct
        return None

    def tool_available(self, name: str) -> bool:
        return self.resolve_tool_path(name) is not None

    def command_env(self) -> dict[str, str]:
        env = os.environ.copy()
        extra_dirs = []
        for directory in self.search_dirs():
            if directory.exists():
                resolved = str(directory)
                if resolved not in extra_dirs:
                    extra_dirs.append(resolved)
        if extra_dirs:
            env["PATH"] = os.pathsep.join([*extra_dirs, env.get("PATH", "")])
        return env

    def sanitize_tool_arguments(self, command: list[str]) -> list[str]:
        """Validate and sanitize tool arguments to prevent command injection.

        Args:
            command: The command list to validate.

        Returns:
            The sanitized command list.

        Raises:
            ValueError: If any argument contains shell metacharacters.
        """
        for i, arg in enumerate(command):
            if SHELL_META.search(arg):
                logger.warning(
                    "Suspicious argument at position %d for command %s: contains shell metacharacters",
                    i,
                    command[0] if command else "unknown",
                )
                raise ValueError(
                    f"Argument {i!r} contains shell metacharacters: {arg!r}. "
                    "Command injection prevention: arguments must not contain ; | & $ ` newline or carriage return."
                )
        return list(command)

    def resolve_command(self, command: list[str]) -> list[str]:
        if not command:
            return command
        resolved = self.resolve_tool_path(command[0])
        if resolved:
            return [resolved, *command[1:]]
        return command

    def run_command(
        self,
        command: list[str],
        timeout: int | None = None,
        stdin_text: str | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> str:
        sanitized = self.sanitize_tool_arguments(command)
        tool_name = sanitized[0] if sanitized else "unknown"
        breaker = get_circuit_breaker(tool_name)
        resolved_command = self.resolve_command(sanitized)
        if not breaker.can_execute():
            raise ToolExecutionError(resolved_command, 1, f"Circuit breaker OPEN for {tool_name}")
        policy = retry_policy or RetryPolicy()
        last_error: Exception | None = None
        for attempt in range(1, policy.max_attempts + 1):
            try:
                process = subprocess.run(
                    resolved_command,
                    input=stdin_text,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    capture_output=True,
                    timeout=timeout or int(TIMEOUT_DEFAULTS["tool_command_seconds"]),
                    check=False,
                    env=self.command_env(),
                )
            except subprocess.TimeoutExpired as exc:
                breaker.record_failure()
                last_error = exc
                if not policy.retry_on_timeout or not self._prepare_retry(
                    resolved_command,
                    attempt,
                    f"timed out after {timeout or int(TIMEOUT_DEFAULTS['tool_command_seconds'])} seconds",
                    policy,
                ):
                    raise
                continue

            if process.returncode == 0:
                breaker.record_success()
                return process.stdout

            breaker.record_failure()

            error = ToolExecutionError(resolved_command, process.returncode, process.stderr)
            last_error = error
            if not policy.retry_on_error or not self._prepare_retry(
                resolved_command,
                attempt,
                f"failed with exit code {process.returncode}",
                policy,
            ):
                raise error

        if last_error:
            raise last_error
        return ""

    def execute_command(
        self,
        command: list[str],
        timeout: int | None = None,
        stdin_text: str | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> ToolExecutionOutcome:
        sanitized = self.sanitize_tool_arguments(command)
        tool_name = sanitized[0] if sanitized else "unknown"
        breaker = get_circuit_breaker(tool_name)
        resolved_command = self.resolve_command(sanitized)
        effective_timeout_seconds = timeout or int(TIMEOUT_DEFAULTS["tool_command_seconds"])
        if not breaker.can_execute():
            error_message = f"Circuit breaker OPEN for {tool_name}"
            return ToolExecutionOutcome(
                command=resolved_command,
                returncode=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=effective_timeout_seconds,
                classification="error",
                fatal=True,
                error_message=error_message,
                warning_messages=[error_message],
            )

        policy = retry_policy or RetryPolicy()
        last_outcome = ToolExecutionOutcome(
            command=resolved_command,
            configured_timeout_seconds=timeout,
            effective_timeout_seconds=effective_timeout_seconds,
        )
        for attempt in range(1, policy.max_attempts + 1):
            started = time.monotonic()
            try:
                process = subprocess.run(
                    resolved_command,
                    input=stdin_text,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    capture_output=True,
                    timeout=effective_timeout_seconds,
                    check=False,
                    env=self.command_env(),
                )
            except subprocess.TimeoutExpired as exc:
                breaker.record_failure()
                timeout_stderr = self._coerce_output_text(exc.stderr)
                last_outcome = ToolExecutionOutcome(
                    command=resolved_command,
                    stdout=self._coerce_output_text(exc.stdout),
                    stderr_lines=self._stderr_lines(timeout_stderr),
                    returncode=-1,
                    timed_out=True,
                    configured_timeout_seconds=timeout,
                    effective_timeout_seconds=effective_timeout_seconds,
                    attempt_count=attempt,
                    classification="timeout",
                    fatal=True,
                    warning_messages=[
                        f"Command {resolved_command!r} timed out after {effective_timeout_seconds} seconds"
                    ],
                    error_message=(
                        f"Command {resolved_command!r} timed out after {effective_timeout_seconds} seconds"
                    ),
                    duration_seconds=time.monotonic() - started,
                )
                if not policy.retry_on_timeout or not self._prepare_retry(
                    resolved_command,
                    attempt,
                    f"timed out after {effective_timeout_seconds} seconds",
                    policy,
                ):
                    return last_outcome
                continue
            except OSError as exc:
                breaker.record_failure()
                error_message = f"Command execution failed: {exc}"
                return ToolExecutionOutcome(
                    command=resolved_command,
                    returncode=1,
                    configured_timeout_seconds=timeout,
                    effective_timeout_seconds=effective_timeout_seconds,
                    attempt_count=attempt,
                    classification="error",
                    fatal=True,
                    warning_messages=[error_message],
                    error_message=error_message,
                    duration_seconds=time.monotonic() - started,
                )
            except Exception as exc:
                breaker.record_failure()
                error_message = f"Unexpected error in command execution: {exc}"
                return ToolExecutionOutcome(
                    command=resolved_command,
                    returncode=1,
                    configured_timeout_seconds=timeout,
                    effective_timeout_seconds=effective_timeout_seconds,
                    attempt_count=attempt,
                    classification="error",
                    fatal=True,
                    warning_messages=[error_message],
                    error_message=error_message,
                    duration_seconds=time.monotonic() - started,
                )

            stderr_lines = self._stderr_lines(process.stderr)
            stderr_classification = classify_stderr_lines(stderr_lines)

            if process.returncode == 0:
                breaker.record_success()
                classification = "ok"
                if stderr_classification.warning_count:
                    classification = "warning"
                return ToolExecutionOutcome(
                    command=resolved_command,
                    stdout=process.stdout,
                    stderr_lines=stderr_lines,
                    returncode=process.returncode,
                    timed_out=False,
                    configured_timeout_seconds=timeout,
                    effective_timeout_seconds=effective_timeout_seconds,
                    attempt_count=attempt,
                    classification=classification,
                    fatal=False,
                    warning_messages=stderr_classification.nonfatal_lines,
                    error_message="",
                    duration_seconds=time.monotonic() - started,
                )

            breaker.record_failure()
            error_message = (
                stderr_classification.best_fatal_line or stderr_classification.best_warning_line
            )
            if not error_message:
                error_message = f"Command failed with exit code {process.returncode}"
            last_outcome = ToolExecutionOutcome(
                command=resolved_command,
                stdout=process.stdout,
                stderr_lines=stderr_lines,
                returncode=process.returncode,
                timed_out=False,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=effective_timeout_seconds,
                attempt_count=attempt,
                classification="error",
                fatal=True,
                warning_messages=stderr_classification.nonfatal_lines,
                error_message=error_message,
                duration_seconds=time.monotonic() - started,
            )
            if not policy.retry_on_error or not self._prepare_retry(
                resolved_command,
                attempt,
                f"failed with exit code {process.returncode}",
                policy,
            ):
                return last_outcome

        return last_outcome

    def try_command(
        self,
        command: list[str],
        timeout: int | None = None,
        stdin_text: str | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> str:
        outcome = self.execute_command(
            command,
            timeout=timeout,
            stdin_text=stdin_text,
            retry_policy=retry_policy,
        )
        emitted = False
        for message in outcome.warning_messages:
            text = str(message or "").strip()
            if not text:
                continue
            emit_warning(text)
            emitted = True
        if outcome.error_message and not emitted:
            emit_warning(outcome.error_message)
        return outcome.stdout

    def projectdiscovery_httpx_available(self) -> bool:
        httpx_path = self.resolve_tool_path("httpx")
        if not httpx_path:
            return False
        try:
            output = subprocess.run(
                [httpx_path, "-h"],
                text=True,
                encoding="utf-8",
                errors="ignore",
                capture_output=True,
                timeout=8,
                check=False,
                env=self.command_env(),
            )
        except OSError:
            return False
        except Exception:
            return False

        combined = f"{output.stdout}\n{output.stderr}".lower()
        return "projectdiscovery" in combined or "-json" in combined

    @classmethod
    def _prepare_retry(
        cls,
        command: list[str],
        attempt: int,
        reason: str,
        policy: RetryPolicy,
    ) -> bool:
        if not retry_ready(policy, attempt):
            return False
        delay = policy.delay_for_attempt(attempt + 1)
        emit_retry_warning(
            "command " + " ".join(command),
            reason=reason,
            attempt=attempt,
            max_attempts=policy.max_attempts,
            delay=delay,
        )
        sleep_before_retry(policy, attempt)
        return True

    @staticmethod
    def _coerce_output_text(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        return value

    @classmethod
    def _stderr_lines(cls, stderr_text: str | bytes | None) -> list[str]:
        return [
            line.strip()
            for line in cls._coerce_output_text(stderr_text).splitlines()
            if line.strip()
        ]

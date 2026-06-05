"""Tool execution service for running external security testing tools.

Provides ToolExecutionService for resolving tool paths, executing commands
with retry support, and managing environment variables for external tools.

Also provides the canonical `run_external_tool()` function and the
`ToolInvocation` / `CompletedToolRun` contract for all external binary execution.
"""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from src.core.contracts.pipeline import TIMEOUT_DEFAULTS
from src.core.logging.pipeline_logging import emit_retry_warning, emit_warning
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.stderr_classification import StderrClassification, classify_stderr_lines
from src.pipeline.retry import RetryPolicy, retry_ready, sleep_before_retry

from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerStats,
    ProbeCallback,
)

logger = get_pipeline_logger(__name__)

SHELL_META = re.compile(r"[;|&$`\n\r]")


def _clean_env(env: dict[str, str] | None) -> dict[str, str]:
    if env is None:
        return {}
    clean = {}
    for k, v in env.items():
        try:
            k_str = str(k)
            v_str = str(v)
            if sys.platform.startswith("win"):
                k_str.encode("utf-8")
                v_str.encode("utf-8")
            clean[k_str] = v_str
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
    return clean


def _get_creationflags() -> int:
    if sys.platform.startswith("win"):
        return subprocess.CREATE_NO_WINDOW
    return 0


_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}
_CIRCUIT_BREAKER_LAST_ACCESS: dict[str, float] = {}
_CIRCUIT_BREAKERS_LOCK = threading.Lock()
# TTL eviction: prune stale circuit-breaker entries on each access (_CIRCUIT_BREAKERS_TTL_SECONDS)
_CIRCUIT_BREAKER_LAST_PRUNED: float = 0.0
_CIRCUIT_BREAKERS_TTL_SECONDS: int = 3600

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


def _get_context_key() -> str:
    import threading

    thread_id = threading.get_ident()
    try:
        task = asyncio.current_task()
        if task is not None:
            task_id = str(id(task))
        else:
            task_id = "none"
    except RuntimeError:
        task_id = "none"
    return f"{thread_id}:{task_id}"


def get_circuit_breaker(tool_name: str) -> CircuitBreaker:
    global _CIRCUIT_BREAKER_LAST_PRUNED
    now = time.monotonic()
    context_key = _get_context_key()
    key = f"{context_key}:{tool_name}"
    with _CIRCUIT_BREAKERS_LOCK:
        breaker = _CIRCUIT_BREAKERS.get(key)
        if breaker is None:
            breaker = CircuitBreaker()
            _CIRCUIT_BREAKERS[key] = breaker
        _CIRCUIT_BREAKER_LAST_ACCESS[key] = now
        if now - _CIRCUIT_BREAKER_LAST_PRUNED > _CIRCUIT_BREAKERS_TTL_SECONDS:
            _CIRCUIT_BREAKER_LAST_PRUNED = now
            for name in list(_CIRCUIT_BREAKERS):
                last_access = _CIRCUIT_BREAKER_LAST_ACCESS.get(name, now)
                if now - last_access > _CIRCUIT_BREAKERS_TTL_SECONDS:
                    _CIRCUIT_BREAKERS.pop(name, None)
                    _CIRCUIT_BREAKER_LAST_ACCESS.pop(name, None)
        return breaker


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
    if invocation.timeout_seconds is None:
        timeout: float | None = float(int(TIMEOUT_DEFAULTS["tool_command_seconds"]))
    elif int(invocation.timeout_seconds) == 0:
        # 0 means "no timeout" - matches ToolExecutionService._resolve_timeout semantics
        timeout = None
    else:
        timeout = float(int(invocation.timeout_seconds))
    env = invocation.env
    cwd = str(invocation.working_dir) if invocation.working_dir else None

    base_env = _clean_env(os.environ.copy())
    if env:
        merged_env = {**base_env, **_clean_env(env)}
    else:
        merged_env = base_env

    try:
        loop = asyncio.get_running_loop()
        process = await loop.run_in_executor(
            None,
            functools.partial(
                subprocess.run,
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
                creationflags=_get_creationflags(),
            ),
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
    circuit_breaker_state: str = ""
    circuit_breaker_skipped: bool = False

    @property
    def stderr_text(self) -> str:
        return "\n".join(self.stderr_lines)

    @property
    def circuit_breaker_open(self) -> bool:
        """Convenience accessor: was the call short-circuited by an OPEN breaker?"""
        return self.circuit_breaker_skipped


class ToolExecutionService:
    """Service for resolving and executing external security tools.

    Each instance owns its own ``dict[str, CircuitBreaker]`` keyed by tool
    name so that breakers are isolated per service instance.  Callers can
    supply per-tool :class:`CircuitBreakerConfig` overrides at construction
    time to tune ``failure_threshold`` and ``recovery_timeout`` (e.g.
    ``nuclei`` recovers in 60 s, a blacklisted ``crt.sh`` may need 10
    minutes).

    The self-healing controller can call :meth:`force_open_breaker` when
    monitoring detects sustained error rates, and the coordinator can
    register per-tool :meth:`schedule_recovery_probe` callbacks to run
    cheap health probes the moment the breaker transitions to HALF_OPEN.
    """

    def __init__(
        self,
        *,
        default_breaker_config: CircuitBreakerConfig | None = None,
        breaker_config_by_tool: dict[str, CircuitBreakerConfig] | None = None,
    ) -> None:
        # Instance-level circuit breakers so each service instance has an isolated state.
        # This prevents cross-test pollution when tests create fresh ToolExecutionService
        # instances in setUp.
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._default_breaker_config: CircuitBreakerConfig = (
            default_breaker_config or CircuitBreakerConfig()
        )
        self._breaker_config_by_tool: dict[str, CircuitBreakerConfig] = (
            dict(breaker_config_by_tool) if breaker_config_by_tool else {}
        )
        self._recovery_probes: dict[str, ProbeCallback] = {}

    def configure_breaker(
        self,
        tool_name: str,
        config: CircuitBreakerConfig,
        *,
        reset_existing: bool = False,
    ) -> CircuitBreaker:
        """Install (or replace) a per-tool breaker config.

        Args:
            tool_name: The external tool to bind the config to.
            config: Tunables (threshold, recovery_timeout, etc.).
            reset_existing: If ``True`` and a breaker already exists for the
                tool, drop it so the new config takes effect immediately.
                The next call will create a fresh breaker with the new
                config applied.  Default ``False`` keeps the existing
                breaker (the new config is recorded for future inspection
                but live state is preserved).
        """
        self._breaker_config_by_tool[tool_name] = config
        if reset_existing:
            self._circuit_breakers.pop(tool_name, None)
        return self._get_circuit_breaker(tool_name)

    def _get_circuit_breaker(self, tool_name: str) -> CircuitBreaker:
        breaker = self._circuit_breakers.get(tool_name)
        if breaker is not None:
            return breaker
        config = self._breaker_config_by_tool.get(tool_name, self._default_breaker_config)
        breaker = CircuitBreaker(
            name=tool_name,
            failure_threshold=config.failure_threshold,
            recovery_timeout=config.recovery_timeout,
        )
        if config.force_open_initial:
            breaker.force_open(
                reason=config.force_open_reason or "configured-initial",
                duration_seconds=config.force_open_duration_seconds or None,
            )
        probe = self._recovery_probes.get(tool_name)
        if probe is not None:
            breaker.schedule_recovery_probe(probe)
        self._circuit_breakers[tool_name] = breaker
        return breaker

    # ------------------------------------------------------------------ #
    # Self-healing controller hot-path                                     #
    # ------------------------------------------------------------------ #

    def force_open_breaker(
        self,
        tool_name: str,
        reason: str,
        duration_seconds: float | None = None,
    ) -> CircuitBreaker:
        """Trip a tool's breaker externally.

        Used by the self-healing controller when monitoring detects
        sustained error rates.  While force-opened the breaker rejects
        calls regardless of ``recovery_timeout``; a subsequent successful
        call clears the forced state and returns the breaker to its normal
        failure-driven path.

        Args:
            tool_name: External tool to trip.
            reason: Human-readable reason, used in logs and the breaker
                stats payload.
            duration_seconds: Fixed cool-down.  ``None`` defaults to the
                breaker's ``recovery_timeout``.  ``0`` keeps the breaker
                open until :meth:`reset_breaker` is invoked or a probe
                succeeds.

        Returns:
            The breaker instance that was tripped.
        """
        breaker = self._get_circuit_breaker(tool_name)
        if duration_seconds is None:
            duration_seconds = breaker.recovery_timeout
        breaker.force_open(
            reason=reason,
            duration_seconds=duration_seconds,
        )
        return breaker

    def reset_breaker(self, tool_name: str) -> CircuitBreaker:
        """Manually reset a tool's breaker to CLOSED."""
        return self._get_circuit_breaker(tool_name).reset()

    def schedule_recovery_probe(
        self,
        tool_name: str,
        callback: ProbeCallback,
    ) -> None:
        """Register a recovery probe callback for a tool.

        The coordinator consumes pending probes via
        :meth:`consume_pending_probes` and invokes the callback exactly
        once per HALF_OPEN transition.  Probes are typically low-cost
        liveness checks (``tool -version`` or a single guarded request)
        used to confirm a tool has recovered before real traffic resumes.
        """
        self._recovery_probes[tool_name] = callback
        existing = self._circuit_breakers.get(tool_name)
        if existing is not None:
            existing.schedule_recovery_probe(callback)

    def consume_pending_probes(self) -> dict[str, ProbeCallback]:
        """Drain all HALF_OPEN probe callbacks across every tool.

        Returns:
            A mapping of ``tool_name -> probe callback`` for tools whose
            breakers just transitioned to ``HALF_OPEN`` since the last
            drain.  The coordinator invokes each callback (e.g. on a
            background task) to test recovery.
        """
        pending: dict[str, ProbeCallback] = {}
        for tool_name, breaker in list(self._circuit_breakers.items()):
            callback = breaker.consume_pending_probe()
            if callback is not None:
                pending[tool_name] = callback
        return pending

    def breaker_snapshot(self) -> dict[str, CircuitBreakerStats]:
        """Return a serializable snapshot of every per-tool breaker.

        Suitable for telemetry, self-healing metrics, and the dashboard.
        """
        return {
            tool_name: breaker.stats()
            for tool_name, breaker in self._circuit_breakers.items()
        }

    def known_tool_names(self) -> list[str]:
        return sorted(self._circuit_breakers.keys())

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
        candidates = self.candidate_paths(name)
        if candidates:
            return str(candidates[0])
        return shutil.which(name)

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
        return _clean_env(env)

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
        breaker = self._get_circuit_breaker(tool_name)
        resolved_command = self.resolve_command(sanitized)
        if not breaker.can_execute():
            raise ToolExecutionError(
                resolved_command,
                1,
                f"Circuit breaker OPEN for {tool_name} (state={breaker.state})",
            )
        policy = retry_policy or RetryPolicy()
        last_error: Exception | None = None
        timeout_arg, timeout_effective = self._resolve_timeout(timeout)
        for attempt in range(1, policy.max_attempts + 1):
            try:
                process = subprocess.run(  # noqa: S603
                    resolved_command,
                    input=stdin_text,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    capture_output=True,
                    timeout=timeout_arg,
                    check=False,
                    env=self.command_env(),
                    creationflags=_get_creationflags(),
                )
            except subprocess.TimeoutExpired as exc:
                breaker.record_failure()
                last_error = exc
                if not policy.retry_on_timeout or not self._prepare_retry(
                    resolved_command,
                    attempt,
                    f"timed out after {timeout_effective} seconds",
                    policy,
                ):
                    raise
                continue

            if process.returncode == 0:
                breaker.record_success()
                return self._maybe_redact_echoed_stdin(process.stdout, stdin_text)

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
        breaker = self._get_circuit_breaker(tool_name)
        resolved_command = self.resolve_command(sanitized)
        timeout_arg, effective_timeout_seconds = self._resolve_timeout(timeout)
        if not breaker.can_execute():
            error_message = f"Circuit breaker OPEN for {tool_name} (state={breaker.state})"
            return ToolExecutionOutcome(
                command=resolved_command,
                returncode=1,
                configured_timeout_seconds=timeout,
                effective_timeout_seconds=effective_timeout_seconds,
                classification="error",
                fatal=True,
                error_message=error_message,
                warning_messages=[error_message],
                circuit_breaker_state=breaker.state,
                circuit_breaker_skipped=True,
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
                process = subprocess.run(  # noqa: S603
                    resolved_command,
                    input=stdin_text,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    capture_output=True,
                    timeout=timeout_arg,
                    check=False,
                    env=self.command_env(),
                    creationflags=_get_creationflags(),
                )
            except subprocess.TimeoutExpired as exc:
                breaker.record_failure()
                timeout_stderr = self._coerce_output_text(exc.stderr)
                last_outcome = ToolExecutionOutcome(
                    command=resolved_command,
                    stdout=self._maybe_redact_echoed_stdin(
                        self._coerce_output_text(exc.stdout),
                        stdin_text,
                    ),
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
                    circuit_breaker_state=breaker.state,
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
                    circuit_breaker_state=breaker.state,
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
                    circuit_breaker_state=breaker.state,
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
                    stdout=self._maybe_redact_echoed_stdin(process.stdout, stdin_text),
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
                    circuit_breaker_state=breaker.state,
                )

            breaker.record_failure()
            error_message = (
                stderr_classification.best_fatal_line or stderr_classification.best_warning_line
            )
            if not error_message:
                error_message = f"Command failed with exit code {process.returncode}"
            last_outcome = ToolExecutionOutcome(
                command=resolved_command,
                stdout=self._maybe_redact_echoed_stdin(process.stdout, stdin_text),
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
                circuit_breaker_state=breaker.state,
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
            output = subprocess.run(  # noqa: S603
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
            logger.debug("tool_detection: OSError probing %s", "httpx")
            return False
        except Exception:
            logger.debug("tool_detection: unexpected error probing %s", "httpx", exc_info=True)
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
            "command " + cls._redact_command_for_logging(command),
            reason=reason,
            attempt=attempt,
            max_attempts=policy.max_attempts,
            delay=delay,
        )
        sleep_before_retry(policy, attempt)
        return True

    @staticmethod
    def _resolve_timeout(timeout: int | None) -> tuple[float | None, int]:
        """Return (timeout_arg_for_subprocess, effective_timeout_seconds).

        Semantics:
        - timeout is None -> use configured default.
        - timeout == 0 -> no timeout.
        - timeout > 0 -> that timeout.
        """
        default = int(TIMEOUT_DEFAULTS["tool_command_seconds"])
        if timeout is None:
            return float(default), default
        parsed = int(timeout)
        if parsed == 0:
            return None, 0
        return float(parsed), parsed

    @staticmethod
    def _maybe_redact_echoed_stdin(stdout: str, stdin_text: str | None) -> str:
        """Best-effort redaction when a child process echoes small stdin secrets."""
        if not stdout or not stdin_text:
            return stdout
        # Avoid redacting large/batch stdin payloads (common for URL lists).
        if "\n" in stdin_text or "\r" in stdin_text or len(stdin_text) > 256:
            return stdout
        if stdin_text not in stdout:
            return stdout
        return stdout.replace(stdin_text, "[REDACTED_STDIN]")

    @classmethod
    def _redact_command_for_logging(cls, command: list[str]) -> str:
        """Redact obvious secrets in command args before logging."""
        redacted: list[str] = []
        for arg in command:
            redacted.append(cls._redact_arg_for_logging(str(arg)))
        return " ".join(redacted)

    @staticmethod
    def _redact_arg_for_logging(arg: str) -> str:
        raw = str(arg)
        lowered = raw.lower()

        # Redact common flag forms: --token=..., --api-key=..., etc.
        for key in ("token", "api-key", "apikey", "password", "passwd", "pwd", "secret", "key"):
            prefix = f"--{key}="
            if lowered.startswith(prefix):
                return raw.split("=", 1)[0] + "=[REDACTED]"

        # Redact Authorization-like headers.
        if "authorization" in lowered or lowered.startswith("bearer "):
            if ":" in raw:
                head, _ = raw.split(":", 1)
                return f"{head}: [REDACTED]"
            return "[REDACTED]"

        # Redact URL credentials (scheme://user:pass@host/...).
        try:
            parts = urlsplit(raw)
            if parts.scheme and parts.netloc and "@" in parts.netloc:
                userinfo, hostport = parts.netloc.rsplit("@", 1)
                if ":" in userinfo:
                    user, _pwd = userinfo.split(":", 1)
                    netloc = f"{user}:[REDACTED]@{hostport}"
                else:
                    netloc = f"[REDACTED]@{hostport}"
                return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        except Exception as e:
            logger.debug("Failed to parse URL for logging redaction: %s", e)

        return raw

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

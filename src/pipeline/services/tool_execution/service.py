"""ToolExecutionService — high-level facade for resolving, validating, and
executing external security tools with circuit-breaker and retry support.

Re-exported at the package level from ``src.pipeline.services.tool_execution``
so existing import paths continue to work.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from src.core.contracts.pipeline import TIMEOUT_DEFAULTS
from src.core.logging.pipeline_logging import emit_retry_warning, emit_warning
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.stderr_classification import StderrClassification, classify_stderr_lines
from src.pipeline.retry import RetryPolicy, retry_ready, sleep_before_retry
from src.pipeline.retry.strategies import detect_rate_limit, parse_retry_after
from src.pipeline.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerStats,
    ProbeCallback,
    load_all_breakers,
    persist_all_breakers,
)
from src.pipeline.waf_profile import WafTuningProfile

from .contracts import ToolExecutionError, ToolExecutionOutcome

logger = get_pipeline_logger(__name__)

SHELL_META = re.compile(r"[;|&\$\`\n\r]")


def _get_creationflags() -> int:
    if sys.platform.startswith("win"):
        return subprocess.CREATE_NO_WINDOW
    return 0


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
        """Install (or replace) a per-tool breaker config."""
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
        """Trip a tool's breaker externally."""
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
        breaker = self._get_circuit_breaker(tool_name)
        breaker.reset()
        return breaker

    def schedule_recovery_probe(
        self,
        tool_name: str,
        callback: ProbeCallback,
    ) -> None:
        """Register a recovery probe callback for a tool."""
        self._recovery_probes[tool_name] = callback
        existing = self._circuit_breakers.get(tool_name)
        if existing is not None:
            existing.schedule_recovery_probe(callback)

    def consume_pending_probes(self) -> dict[str, ProbeCallback]:
        """Drain all HALF_OPEN probe callbacks across every tool."""
        pending: dict[str, ProbeCallback] = {}
        for tool_name, breaker in list(self._circuit_breakers.items()):
            callback = breaker.consume_pending_probe()
            if callback is not None:
                pending[tool_name] = callback
        return pending

    def breaker_snapshot(self) -> dict[str, CircuitBreakerStats]:
        """Return a serializable snapshot of every per-tool breaker."""
        return {tool_name: breaker.stats() for tool_name, breaker in self._circuit_breakers.items()}

    def persist_breaker_states(self, cache: Any) -> None:
        from .runner import persist_all_breakers
        persist_all_breakers(cache, self._circuit_breakers)

    def restore_breaker_states(self, cache: Any) -> None:
        from .runner import load_all_breakers
        restored = load_all_breakers(cache)
        for name, state_dict in restored.items():
            if name not in self._circuit_breakers:
                config = CircuitBreakerConfig(
                    failure_threshold=int(state_dict.get("failure_threshold", 5)),
                    recovery_timeout=float(state_dict.get("recovery_timeout", 60.0)),
                )
                breaker = CircuitBreaker(
                    name=name,
                    failure_threshold=config.failure_threshold,
                    recovery_timeout=config.recovery_timeout,
                )
                if (
                    state_dict.get("forced_open")
                    and state_dict.get("force_open_until", 0) > time.time()
                ):
                    remaining = state_dict["force_open_until"] - time.time()
                    breaker.force_open(
                        reason=str(state_dict.get("force_open_reason", "recovered")),
                        duration_seconds=remaining,
                    )
                self._circuit_breakers[name] = breaker
            else:
                existing = self._circuit_breakers[name]
                if (
                    state_dict.get("forced_open")
                    and state_dict.get("force_open_until", 0) > time.time()
                ):
                    remaining = state_dict["force_open_until"] - time.time()
                    existing.force_open(
                        reason=str(state_dict.get("force_open_reason", "recovered")),
                        duration_seconds=remaining,
                    )

    def known_tool_names(self) -> list[str]:
        return sorted(self._circuit_breakers.keys())

    def search_dirs(self) -> list[Path]:
        """Return directories to search for external tool binaries."""
        user_home = Path.home()
        workspace_root = Path(__file__).resolve().parents[2]
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
        return self._clean_env(env)

    def sanitize_tool_arguments(self, command: list[str]) -> list[str]:
        """Validate and sanitize tool arguments to prevent command injection."""
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
        waf_profile: WafTuningProfile | None = None,
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
                if not policy.retry_on_timeout or not self._prepare_retry_with_stderr(
                    resolved_command,
                    attempt,
                    f"timed out after {timeout_effective} seconds",
                    policy,
                    stderr_text=self._coerce_output_text(exc.stderr),
                    waf_profile=waf_profile,
                ):
                    raise
                continue

            if process.returncode == 0:
                breaker.record_success()
                return self._maybe_redact_echoed_stdin(process.stdout, stdin_text)

            breaker.record_failure()

            error = ToolExecutionError(resolved_command, process.returncode, process.stderr)
            last_error = error
            if not policy.retry_on_error or not self._prepare_retry_with_stderr(
                resolved_command,
                attempt,
                f"failed with exit code {process.returncode}",
                policy,
                stderr_text=process.stderr,
                waf_profile=waf_profile,
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
        waf_profile: WafTuningProfile | None = None,
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
                if not policy.retry_on_timeout or not self._prepare_retry_with_stderr(
                    resolved_command,
                    attempt,
                    f"timed out after {effective_timeout_seconds} seconds",
                    policy,
                    stderr_text=timeout_stderr,
                    waf_profile=waf_profile,
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
            if not policy.retry_on_error or not self._prepare_retry_with_stderr(
                resolved_command,
                attempt,
                f"failed with exit code {process.returncode}",
                policy,
                stderr_text=process.stderr,
                waf_profile=waf_profile,
            ):
                return last_outcome

        return last_outcome

    def try_command(
        self,
        command: list[str],
        timeout: int | None = None,
        stdin_text: str | None = None,
        retry_policy: RetryPolicy | None = None,
        waf_profile: WafTuningProfile | None = None,
    ) -> str:
        outcome = self.execute_command(
            command,
            timeout=timeout,
            stdin_text=stdin_text,
            retry_policy=retry_policy,
            waf_profile=waf_profile,
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

    def get_tool_version(self, name: str) -> str | None:
        """Return the version string of an external tool, if detectable."""
        path = self.resolve_tool_path(name)
        if not path:
            return None
        for flag in ("-version", "--version", "-v"):
            try:
                proc = subprocess.run(  # noqa: S603
                    [path, flag],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    capture_output=True,
                    timeout=8,
                    check=False,
                    env=self.command_env(),
                )
                output = (proc.stdout or proc.stderr or "").strip()
                if output:
                    return output.splitlines()[0][:256]
            except Exception:
                logger.debug("Failed to get version with flag %s: %s", flag, exc_info=True)
                continue
        return None

    def _compute_retry_delay(
        self,
        policy: Any,
        attempt_number: int,
        stderr_text: str = "",
        waf_profile: WafTuningProfile | None = None,
    ) -> float:
        """Return backoff delay, honouring Retry-After when present."""
        retry_after = parse_retry_after(stderr_text)
        if retry_after is not None:
            return float(retry_after)
        base = float(policy.delay_for_attempt(attempt_number))
        if waf_profile is not None and detect_rate_limit(stderr_text):
            return max(base, waf_profile.recovery_timeout_seconds)
        return base

    def _prepare_retry_with_stderr(
        self,
        command: list[str],
        attempt: int,
        reason: str,
        policy: Any,
        stderr_text: str = "",
        waf_profile: WafTuningProfile | None = None,
    ) -> bool:
        if not retry_ready(policy, attempt):
            return False
        delay = self._compute_retry_delay(policy, attempt + 1, stderr_text, waf_profile)
        emit_retry_warning(
            "command " + self._redact_command_for_logging(command),
            reason=reason,
            attempt=attempt,
            max_attempts=policy.max_attempts,
            delay=delay,
        )
        sleep_before_retry(policy, attempt)
        return True

    def _prepare_retry(
        self,
        command: list[str],
        attempt: int,
        reason: str,
        policy: RetryPolicy,
    ) -> bool:
        if not retry_ready(policy, attempt):
            return False
        delay = policy.delay_for_attempt(attempt + 1)
        emit_retry_warning(
            "command " + self._redact_command_for_logging(command),
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

        for key in ("token", "api-key", "apikey", "password", "passwd", "pwd", "secret", "key"):
            prefix = f"--{key}="
            if lowered.startswith(prefix):
                return raw.split("=", 1)[0] + "=[REDACTED]"

        if "authorization" in lowered or lowered.startswith("bearer "):
            if ":" in raw:
                head, _ = raw.split(":", 1)
                return f"{head}: [REDACTED]"
            return "[REDACTED]"

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
    def _clean_env(env: dict[str, str] | None) -> dict[str, str]:
        if env is None:
            return {}
        clean = {}
        for k, v in env.items():
            try:
                k_str = str(k)
                v_str = str(v)
                k_str.encode("utf-8")
                v_str.encode("utf-8")
                clean[k_str] = v_str
            except (UnicodeEncodeError, UnicodeDecodeError) as exc:
                logger.warning("Dropped environment variable %r due to encoding error: %s", k, exc)
                continue
        return clean

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

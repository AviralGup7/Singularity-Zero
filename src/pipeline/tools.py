"""Tool execution facade providing a default ToolExecutionService singleton.

Provides functions for running external security testing tools
(subfinder, httpx, nuclei, etc.) with retry support.
"""

from typing import Any

from src.pipeline.retry import RetryPolicy
from src.pipeline.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerStats,
    ProbeCallback,
)
from src.pipeline.services.tool_execution import (
    ToolExecutionError,
    ToolExecutionOutcome,
    ToolExecutionService,
)

_DEFAULT_TOOL_SERVICE = ToolExecutionService()


def resolve_tool_path(name: str) -> str | None:
    return _DEFAULT_TOOL_SERVICE.resolve_tool_path(name)


def tool_available(name: str) -> bool:
    return _DEFAULT_TOOL_SERVICE.tool_available(name)


def command_env() -> dict[str, str]:
    return _DEFAULT_TOOL_SERVICE.command_env()


def resolve_command(command: list[str]) -> list[str]:
    return _DEFAULT_TOOL_SERVICE.resolve_command(command)


def run_command(
    command: list[str],
    timeout: int | None = None,
    stdin_text: str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> str:
    return _DEFAULT_TOOL_SERVICE.run_command(
        command, timeout=timeout, stdin_text=stdin_text, retry_policy=retry_policy
    )


def try_command(
    command: list[str],
    timeout: int | None = None,
    stdin_text: str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> str:
    return _DEFAULT_TOOL_SERVICE.try_command(
        command, timeout=timeout, stdin_text=stdin_text, retry_policy=retry_policy
    )


def execute_command(
    command: list[str],
    timeout: int | None = None,
    stdin_text: str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> ToolExecutionOutcome:
    return _DEFAULT_TOOL_SERVICE.execute_command(
        command,
        timeout=timeout,
        stdin_text=stdin_text,
        retry_policy=retry_policy,
    )


def projectdiscovery_httpx_available() -> bool:
    return _DEFAULT_TOOL_SERVICE.projectdiscovery_httpx_available()


def get_tool_version(name: str) -> str | None:
    return _DEFAULT_TOOL_SERVICE.get_tool_version(name)


def configure_breaker(
    tool_name: str,
    config: CircuitBreakerConfig,
    *,
    reset_existing: bool = False,
) -> CircuitBreaker:
    """Install a per-tool breaker config on the default service."""
    return _DEFAULT_TOOL_SERVICE.configure_breaker(
        tool_name, config, reset_existing=reset_existing
    )


def force_open_breaker(
    tool_name: str,
    reason: str,
    duration_seconds: float | None = None,
) -> CircuitBreaker:
    """Trip a tool's breaker externally (self-healing controller hot-path)."""
    return _DEFAULT_TOOL_SERVICE.force_open_breaker(
        tool_name, reason, duration_seconds=duration_seconds
    )


def reset_breaker(tool_name: str) -> CircuitBreaker:
    return _DEFAULT_TOOL_SERVICE.reset_breaker(tool_name)


def schedule_recovery_probe(tool_name: str, callback: ProbeCallback) -> None:
    _DEFAULT_TOOL_SERVICE.schedule_recovery_probe(tool_name, callback)


def consume_pending_probes() -> dict[str, ProbeCallback]:
    return _DEFAULT_TOOL_SERVICE.consume_pending_probes()


def breaker_snapshot() -> dict[str, CircuitBreakerStats]:
    return _DEFAULT_TOOL_SERVICE.breaker_snapshot()


def known_tool_names() -> list[str]:
    return _DEFAULT_TOOL_SERVICE.known_tool_names()


def build_retry_policy(
    global_settings: dict[str, Any] | None = None, tool_settings: dict[str, Any] | None = None
) -> RetryPolicy:
    return RetryPolicy.from_settings(global_settings=global_settings, tool_settings=tool_settings)


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerStats",
    "ProbeCallback",
    "RetryPolicy",
    "ToolExecutionError",
    "ToolExecutionOutcome",
    "ToolExecutionService",
    "breaker_snapshot",
    "build_retry_policy",
    "command_env",
    "configure_breaker",
    "consume_pending_probes",
    "execute_command",
    "force_open_breaker",
    "known_tool_names",
    "projectdiscovery_httpx_available",
    "get_tool_version",
    "reset_breaker",
    "resolve_command",
    "resolve_tool_path",
    "run_command",
    "schedule_recovery_probe",
    "tool_available",
    "try_command",
]

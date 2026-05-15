"""Tool execution facade providing a default ToolExecutionService singleton.

Provides functions for running external security testing tools
(subfinder, httpx, nuclei, etc.) with retry support.
"""

from typing import Any

from src.pipeline.retry import RetryPolicy
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


def build_retry_policy(
    global_settings: dict[str, Any] | None = None, tool_settings: dict[str, Any] | None = None
) -> RetryPolicy:
    return RetryPolicy.from_settings(global_settings=global_settings, tool_settings=tool_settings)


__all__ = [
    "RetryPolicy",
    "ToolExecutionError",
    "ToolExecutionOutcome",
    "ToolExecutionService",
    "build_retry_policy",
    "command_env",
    "execute_command",
    "projectdiscovery_httpx_available",
    "resolve_command",
    "resolve_tool_path",
    "run_command",
    "tool_available",
    "try_command",
]

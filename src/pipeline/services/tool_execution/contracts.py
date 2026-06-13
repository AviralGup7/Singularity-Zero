"""Public data contracts and exceptions for tool execution.

Re-exported at the package level from ``src.pipeline.services.tool_execution``
so existing ``from src.pipeline.services.tool_execution import (ToolInvocation,
CompletedToolRun, ToolExecutionOutcome, ToolExecutionError)`` continues to work.
"""

from __future__ import annotations

import dataclasses as _dataclasses
from pathlib import Path

from src.core.utils.stderr_classification import StderrClassification


@_dataclasses.dataclass(slots=True, frozen=True)
class ToolInvocation:
    """Portable description of an external tool invocation.

    This is the ONLY interface for running external binaries in the pipeline.
    All subprocess.run / create_subprocess_exec calls must go through
    run_external_tool() so that timeout handling, stderr classification,
    and environment isolation are applied uniformly.
    """

    tool_name: str
    args: list[str] = _dataclasses.field(default_factory=list)
    timeout_seconds: int | None = None
    env: dict[str, str] | None = None
    working_dir: str | Path | None = None
    stdin: str | None = None

    @property
    def command(self) -> list[str]:
        return [self.tool_name, *self.args]


@_dataclasses.dataclass(slots=True)
class CompletedToolRun:
    """Structured result of an external tool invocation.

    Returned by run_external_tool().  Never raises on timeout —
    timed_out=True indicates the timeout was exceeded.
    """

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    timed_out: bool = False
    timeout_events: list[str] = _dataclasses.field(default_factory=list)
    stderr_classification: StderrClassification | None = None
    duration_seconds: float = 0.0
    tool_name: str = ""

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.exit_code == 0


@_dataclasses.dataclass(slots=True)
class ToolExecutionOutcome:
    command: list[str]
    stdout: str = ""
    stderr_lines: list[str] = _dataclasses.field(default_factory=list)
    returncode: int = 0
    timed_out: bool = False
    configured_timeout_seconds: int | None = None
    effective_timeout_seconds: int | None = None
    attempt_count: int = 1
    classification: str = "ok"
    fatal: bool = False
    warning_messages: list[str] = _dataclasses.field(default_factory=list)
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

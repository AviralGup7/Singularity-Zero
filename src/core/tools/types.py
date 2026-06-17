"""Shared tool execution types for the core layer.

Provides data types used across recon, pipeline, and execution packages
without creating cross-layer dependencies.
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class ToolExecutionOutcome:
    """Result of a tool execution attempt."""

    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False
    retry_count: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "retry_count": self.retry_count,
        }


@dataclasses.dataclass(frozen=True)
class ToolInvocation:
    """Describes a single external tool invocation."""

    tool_name: str
    args: list[str]
    timeout_seconds: int | None = None
    env: dict[str, str] | None = None
    working_dir: str | None = None

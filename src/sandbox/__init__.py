"""PoC / plugin sandbox. The only place WASM execution is advertised."""

from __future__ import annotations

import os
from typing import Any


def wasm_enabled() -> bool:
    return os.getenv("FEATURE_WASM_PLUGINS", "false").strip().lower() in {"1", "true", "yes"}


def execute_plugin(wasm_path: str, stage_input: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    from src.execution.frontier.wasm import execute_sandboxed_plugin

    return execute_sandboxed_plugin(wasm_path, stage_input, **kwargs)


from src.sandbox.process_sandbox import (
    ProcessSandbox,
    SandboxExecutionResult,
    SandboxResourceLimits,
)

__all__ = [
    "ProcessSandbox",
    "SandboxExecutionResult",
    "SandboxResourceLimits",
    "execute_plugin",
    "wasm_enabled",
]

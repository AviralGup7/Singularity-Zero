"""
Cyber Security Test Pipeline - WASM Sandbox Plugins
Typed manifest and helper definitions for running isolated WASM detectors.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
from dataclasses import dataclass
from typing import Any

from src.core.frontier.wasm import execute_sandboxed_plugin


@dataclass
class IsolatedScanner:
    """
    Manifest defining the strict input/output boundaries and resource limits
    for an isolated WASM scanner module.
    """
    plugin_id: str
    wasm_path: str
    allowed_inputs: list[str]
    expected_outputs: list[str]
    memory_limit_mb: int = 128
    timeout_seconds: float = 5.0

    def validate_input(self, stage_input: dict[str, Any]) -> dict[str, Any]:
        """Filter stage input to only contain allowed keys."""
        return {k: v for k, v in stage_input.items() if k in self.allowed_inputs}

    def validate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """Ensure result only returns expected outputs or standard audit fields."""
        allowed_keys = set(self.expected_outputs) | {"verified", "error", "message", "_wasm_duration", "killed"}
        return {k: v for k, v in result.items() if k in allowed_keys}


def execute_isolated_scanner(scanner: IsolatedScanner, stage_input: dict[str, Any]) -> dict[str, Any]:
    """
    Executes a scanner with strict input/output validation and an immutable
    OS-level wall-budget timer.
    """
    filtered_input = scanner.validate_input(stage_input)
    
    # Define an OS-level wall-budget watchdog thread
    timer_fired = False
    
    def watchdog() -> None:
        nonlocal timer_fired
        # Keep timer-fired flag
        timer_fired = True
        # Terminate runaway process immediately using SIGKILL (or SIGTERM on Windows)
        try:
            pid = os.getpid()
            if sys.platform == "win32":
                os.kill(pid, signal.SIGTERM)
            else:
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    # Start the watchdog timer thread
    timer = threading.Timer(scanner.timeout_seconds, watchdog)
    timer.daemon = True
    timer.start()

    try:
        raw_result = execute_sandboxed_plugin(
            scanner.wasm_path,
            filtered_input,
            timeout_seconds=scanner.timeout_seconds,
        )
        return scanner.validate_output(raw_result)
    finally:
        timer.cancel()

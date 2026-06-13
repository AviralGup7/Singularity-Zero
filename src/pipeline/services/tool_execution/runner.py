"""Low-level tool runner, process executor pool, module-level helpers, and the
async ``run_external_tool()`` public entry point.

Re-exported at the package level from ``src.pipeline.services.tool_execution``
so existing import paths continue to work.
"""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import functools
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline import TIMEOUT_DEFAULTS
from src.core.logging.pipeline_logging import emit_retry_warning, emit_warning
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.stderr_classification import StderrClassification, classify_stderr_lines
from src.pipeline.retry import RetryPolicy, retry_ready, sleep_before_retry
from src.pipeline.retry.strategies import detect_rate_limit, parse_retry_after
from src.pipeline.waf_profile import WafTuningProfile

from src.pipeline.services.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerStats,
    ProbeCallback,
    load_all_breakers,
    persist_all_breakers,
)
from .contracts import ToolExecutionOutcome

logger = get_pipeline_logger(__name__)

SHELL_META = re.compile(r"[;|&\$\`\n\r]")


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


def _get_creationflags() -> int:
    if sys.platform.startswith("win"):
        return subprocess.CREATE_NO_WINDOW
    return 0


def _coerce_output_text(value: str | bytes | None) -> str:
    """Coerce subprocess output to string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return value


# --------------------------------------------------------------------------- #
# Module-level circuit-breaker registry (used by run_external_tool)            #
# --------------------------------------------------------------------------- #

_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}
_CIRCUIT_BREAKER_LAST_ACCESS: dict[str, float] = {}
_CIRCUIT_BREAKERS_LOCK = threading.Lock()
_CIRCUIT_BREAKER_LAST_PRUNED: float = 0.0
_CIRCUIT_BREAKERS_TTL_SECONDS: int = 3600
_CIRCUIT_BREAKER_PRUNE_INTERVAL: int = 300
_CIRCUIT_BREAKER_MAX_ENTRIES: int = 500


def get_circuit_breaker(tool_name: str) -> CircuitBreaker:
    global _CIRCUIT_BREAKER_LAST_PRUNED
    now = time.monotonic()
    key = tool_name
    with _CIRCUIT_BREAKERS_LOCK:
        breaker = _CIRCUIT_BREAKERS.get(key)
        if breaker is None:
            if len(_CIRCUIT_BREAKERS) >= _CIRCUIT_BREAKER_MAX_ENTRIES:
                _prune_stale_circuit_breakers(now)
            breaker = CircuitBreaker()
            _CIRCUIT_BREAKERS[key] = breaker
        _CIRCUIT_BREAKER_LAST_ACCESS[key] = now
        if now - _CIRCUIT_BREAKER_LAST_PRUNED > _CIRCUIT_BREAKER_PRUNE_INTERVAL:
            _CIRCUIT_BREAKER_LAST_PRUNED = now
            _prune_stale_circuit_breakers(now)
        return breaker


def _prune_stale_circuit_breakers(now: float) -> None:
    """Remove expired circuit-breaker entries incrementally."""
    stale_keys = [
        name
        for name, last_access in _CIRCUIT_BREAKER_LAST_ACCESS.items()
        if now - last_access > _CIRCUIT_BREAKERS_TTL_SECONDS
    ]
    for name in stale_keys:
        _CIRCUIT_BREAKERS.pop(name, None)
        _CIRCUIT_BREAKER_LAST_ACCESS.pop(name, None)


# --------------------------------------------------------------------------- #
# Thread-pool executor for blocking subprocess calls                            #
# --------------------------------------------------------------------------- #

_TOOL_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None
_TOOL_EXECUTOR_LOCK = threading.Lock()


def _get_tool_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _TOOL_EXECUTOR
    if _TOOL_EXECUTOR is None:
        with _TOOL_EXECUTOR_LOCK:
            if _TOOL_EXECUTOR is None:
                _TOOL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                    max_workers=200, thread_name_prefix="tool_exec"
                )
    return _TOOL_EXECUTOR


def _shutdown_tool_executor() -> None:
    global _TOOL_EXECUTOR
    if _TOOL_EXECUTOR is not None:
        _TOOL_EXECUTOR.shutdown(wait=True, cancel_futures=True)
        _TOOL_EXECUTOR = None


atexit.register(_shutdown_tool_executor)


# --------------------------------------------------------------------------- #
# run_external_tool — unified external binary runner                            #
# --------------------------------------------------------------------------- #


async def run_external_tool(invocation) -> CompletedToolRun:
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
            _get_tool_executor(),
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

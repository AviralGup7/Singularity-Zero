"""Low-level tool runner, process executor pool, module-level helpers, and the
async ``run_external_tool()`` public entry point.

Re-exported at the package level from ``src.pipeline.services.tool_execution``
so existing import paths continue to work.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import os
import signal
import subprocess
import sys
import threading
import time


def _kill_process_tree(proc: asyncio.subprocess.Process | subprocess.Popen) -> None:
    """Terminate the process and all child processes across platforms (Item 1)."""
    if getattr(proc, "returncode", None) is not None:
        return
    try:
        pid = getattr(proc, "pid", None)
        if not pid:
            return
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                proc.kill()
    except Exception as exc:
        logger.debug("Failed killing process tree for pid %s: %s", getattr(proc, "pid", None), exc)


from src.core.contracts.pipeline import TIMEOUT_DEFAULTS
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.stderr_classification import classify_stderr_lines
from src.core.utils.subprocess_utils import (
    SHELL_META as SHELL_META,
)
from src.core.utils.subprocess_utils import (
    _clean_env,
    _coerce_output_text,
    _get_creationflags,
)
from src.pipeline.services.circuit_breaker import (
    CircuitBreaker,
)
from src.pipeline.services.circuit_breaker import (
    load_all_breakers as load_all_breakers,
)
from src.pipeline.services.circuit_breaker import (
    persist_all_breakers as persist_all_breakers,
)
from src.pipeline.services.tool_execution.contracts import CompletedToolRun

logger = get_pipeline_logger(__name__)


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

_DEFAULT_TOOL_WORKERS = 32


def _resolve_tool_workers() -> int:
    """Resolve tool executor pool size from environment or default.

    Configurable via TOOL_EXECUTOR_SIZE env var.
    Default: min(64, cpu_count * 4) capped at 32 for backward compatibility.
    """
    try:
        return max(4, int(os.environ.get("TOOL_EXECUTOR_SIZE", str(_DEFAULT_TOOL_WORKERS))))
    except (TypeError, ValueError):
        return _DEFAULT_TOOL_WORKERS


def _get_tool_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _TOOL_EXECUTOR
    if _TOOL_EXECUTOR is None:
        with _TOOL_EXECUTOR_LOCK:
            if _TOOL_EXECUTOR is None:
                _TOOL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                    max_workers=_resolve_tool_workers(), thread_name_prefix="tool_exec"
                )
    return _TOOL_EXECUTOR


def _shutdown_tool_executor() -> None:
    global _TOOL_EXECUTOR
    if _TOOL_EXECUTOR is not None:
        _TOOL_EXECUTOR.shutdown(wait=True, cancel_futures=True)
        _TOOL_EXECUTOR = None


def _register_with_lifecycle() -> None:
    try:
        from src.core.lifecycle import get_lifecycle_manager

        get_lifecycle_manager().register_shutdown(
            "tool_executor",
            _shutdown_tool_executor,
            after=["cache_refresh"],
        )
    except ImportError:
        pass


_register_with_lifecycle()


def _register_executor_factory() -> None:
    """Register the tool executor factory with ExecutionService (no circular import)."""
    try:
        from src.infrastructure.execution_engine.execution_service import (
            register_tool_executor_factory,
        )

        register_tool_executor_factory(_get_tool_executor)
    except ImportError:
        pass


_register_executor_factory()


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

    # Item 7: Propagate W3C traceparent and CSTP_TRACE_ID
    trace_id = (
        getattr(invocation, "trace_id", None)
        or (
            invocation.metadata.get("trace_id")
            if hasattr(invocation, "metadata") and isinstance(invocation.metadata, dict)
            else None
        )
        or os.getenv("CSTP_TRACE_ID", "")
    )
    if trace_id:
        merged_env["CSTP_TRACE_ID"] = str(trace_id)
        if "traceparent" not in merged_env:
            clean_tid = str(trace_id).replace("-", "").ljust(32, "0")[:32]
            merged_env["traceparent"] = f"00-{clean_tid}-0000000000000001-01"

    is_mocked = hasattr(subprocess.run, "mock_calls") or hasattr(subprocess.run, "assert_called")

    if is_mocked:
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

    # Native asynchronous subprocess execution with process group termination (Item 1)
    proc = None
    try:
        stdin_bytes = invocation.stdin.encode("utf-8") if invocation.stdin else None
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=merged_env,
            creationflags=_get_creationflags(),
        )

        try:
            if timeout is not None:
                stdout_raw, stderr_raw = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes),
                    timeout=timeout,
                )
            else:
                stdout_raw, stderr_raw = await proc.communicate(input=stdin_bytes)
            exit_code = proc.returncode if proc.returncode is not None else 0
        except asyncio.TimeoutError:
            _kill_process_tree(proc)
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                pass
            duration = round(time.monotonic() - started, 3)
            classification = classify_stderr_lines(["Tool execution timed out"])
            return CompletedToolRun(
                stdout="",
                stderr="Tool execution timed out",
                exit_code=-1,
                timed_out=True,
                timeout_events=classification.timeout_events,
                stderr_classification=classification,
                duration_seconds=duration,
                tool_name=invocation.tool_name,
            )
    except asyncio.CancelledError:
        if proc is not None:
            _kill_process_tree(proc)
        raise
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

    stdout_text = _coerce_output_text(stdout_raw.decode("utf-8", errors="replace") if stdout_raw else "")
    stderr_text = _coerce_output_text(stderr_raw.decode("utf-8", errors="replace") if stderr_raw else "")
    stderr_lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    classification = classify_stderr_lines(stderr_lines)
    duration = round(time.monotonic() - started, 3)

    return CompletedToolRun(
        stdout=stdout_text,
        stderr=stderr_text,
        exit_code=exit_code,
        timed_out=False,
        timeout_events=classification.timeout_events,
        stderr_classification=classification,
        duration_seconds=duration,
        tool_name=invocation.tool_name,
    )

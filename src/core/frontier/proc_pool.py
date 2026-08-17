"""
Cyber Security Test Pipeline - Frontier Process Pool
Implements bounded, one-shot subprocess execution for CLI security tools.

Audit Fixes Applied:
- P0: Replaced interactive stdin/stdout protocol with one-shot subprocess execution.
  CLI tools (subfinder, httpx, nuclei, etc.) are NOT persistent JSON-RPC workers.
  They accept command-line arguments, run to completion, and exit.
- P1: Added asyncio.Semaphore to prevent fallback subprocess explosion.
- P1: Added process tree killing (not just parent) on timeout/cleanup.
- P1: Added centralized tool availability verification via verify_all_tools().
- P2: Added tool version detection and logging at warmup time.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

from src.core.frontier.marshaller import safe_pack, safe_unpack
from src.core.frontier.state import stable_digest
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.subprocess_utils import _get_creationflags

logger = get_pipeline_logger(__name__)


def _loop_time() -> float:
    """Return the running event loop's monotonic time.

    Falls back to ``time.monotonic`` when no loop is active, so the
    helper is safe to call from sync code paths and avoids the
    deprecated ``asyncio.get_event_loop()``.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return time.monotonic()
    return loop.time()


try:
    import psutil
except ImportError:
    psutil = None


MAX_PAYLOAD_BYTES = 10_000_000

# Default concurrency cap for one-shot subprocesses spawned by the pool.
# This prevents process tree explosion when the pool is under heavy load.
_DEFAULT_MAX_CONCURRENT = 16


def _decode(value: bytes | str, encoding: str = "utf-8", errors: str = "backslashreplace") -> str:
    return value.decode(encoding, errors) if isinstance(value, bytes) else value


async def _kill_process_tree(proc: asyncio.subprocess.Process, timeout: float = 5.0) -> None:
    """Kill a process and all its descendants (children, grandchildren, ...).

    Uses psutil on all platforms when available, falls back to platform-specific
    commands (taskkill on Windows, killpg on Unix).
    """
    pid = proc.pid
    if pid is None:
        return

    if psutil is not None:
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            # Send SIGTERM to children first (graceful)
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # Then terminate the parent
            try:
                parent.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Wait for graceful shutdown
            gone, alive = psutil.wait_procs([parent] + children, timeout=timeout)

            # Force kill anything still alive
            for p in alive:
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Final wait
            psutil.wait_procs(alive, timeout=2.0)
            return
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Fallback: platform-specific kill
    if sys.platform != "win32":
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGTERM)
            await asyncio.sleep(timeout)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        except (OSError, ProcessLookupError):
            pass
    else:
        # Windows: use taskkill to kill the process tree
        # taskkill is in System32, always in PATH on Windows
        try:
            subprocess.run(  # noqa: S603
                ["taskkill", "/F", "/T", "/PID", str(pid)],  # noqa: S607
                capture_output=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
            except (OSError, ProcessLookupError):
                pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=3.0)
    except (TimeoutError, ProcessLookupError):
        pass


@dataclass
class ProcessTaskReceipt:
    """Durable-enough receipt used by the caller to decide replay after process loss."""

    task_id: str
    tool_name: str
    status: str
    output: str = ""
    error: str = ""
    timestamp: float = 0.0


@dataclass
class ToolVersionInfo:
    """Tracks detected tool version for drift monitoring."""

    name: str
    version: str | None = None
    path: str | None = None
    verified: bool = False


_STALE_TTL = 300
_BINARY_CACHE_MAX = 1000

_ALLOWED_TOOL_NAMES: set[str] = {
    "nuclei",
    "httpx",
    "subfinder",
    "naabu",
    "katana",
    "gau",
    "waybackurls",
    "gobuster",
    "ffuf",
    "feroxbuster",
    "nikto",
    "whatweb",
    "wpscan",
    "sqlmap",
    "dalfox",
}


def _validate_tool_name(tool_name: str) -> None:
    """Validate tool name against allowlist to prevent arbitrary command execution."""
    if tool_name not in _ALLOWED_TOOL_NAMES:
        raise ValueError(
            f"Tool '{tool_name}' is not in the allowed tools list. "
            f"Allowed: {', '.join(sorted(_ALLOWED_TOOL_NAMES))}"
        )


class FrontierProcessPool:
    """
    Managed Execution Pool for CLI security tools.

    Uses bounded one-shot subprocess execution instead of pre-warmed persistent
    processes. CLI tools (subfinder, httpx, nuclei, etc.) are NOT interactive
    workers -- they accept command-line arguments, run to completion, and exit.

    Concurrency is controlled via an asyncio.Semaphore to prevent process tree
    explosion under heavy load. Each task spawns a fresh subprocess, runs it to
    completion, and captures stdout/stderr.
    """

    def __init__(
        self,
        pool_size: int | None = None,
        max_memory_mb: float = 512.0,
        max_concurrent: int = _DEFAULT_MAX_CONCURRENT,
    ) -> None:
        cpu_count = os.cpu_count() or 2
        self.pool_size = pool_size or min(4, cpu_count)
        self._max_concurrent = max_concurrent

        # Semaphore bounds the number of concurrent one-shot subprocesses.
        # Prevents P1 fallback explosion (500 hosts -> 500 subprocesses).
        self._semaphore = asyncio.Semaphore(max_concurrent)

        self._lock = asyncio.Lock()
        self._task_receipts: dict[str, ProcessTaskReceipt] = {}
        self._last_receipt_prune: float = 0.0
        self._base_args_map: dict[str, list[str]] = {}
        self._binary_task_cache: dict[str, Any] = {}
        self._tool_versions: dict[str, ToolVersionInfo] = {}

    def _make_receipt(
        self,
        task_id: str,
        tool_name: str,
        status: str,
        output: str = "",
        error: str = "",
    ) -> ProcessTaskReceipt:
        return ProcessTaskReceipt(
            task_id=task_id,
            tool_name=tool_name,
            status=status,
            output=output,
            error=error,
            timestamp=_loop_time(),
        )

    def _prune_stale_receipts(self) -> None:
        now = _loop_time()
        if now - self._last_receipt_prune < _STALE_TTL:
            return
        self._last_receipt_prune = now
        alive_ids = set(
            tid for tid, r in self._task_receipts.items() if (now - r.timestamp) < _STALE_TTL
        )
        self._task_receipts = {tid: self._task_receipts[tid] for tid in alive_ids}
        self._binary_task_cache = {
            k: v for k, v in self._binary_task_cache.items() if k in alive_ids
        }

    def _cap_task_receipts(self) -> None:
        """Hard-cap _task_receipts to prevent unbounded growth between prune windows."""
        _MAX_RECEIPTS = 10_000
        if len(self._task_receipts) > _MAX_RECEIPTS:
            sorted_keys = sorted(
                self._task_receipts,
                key=lambda k: self._task_receipts[k].timestamp,
            )
            for k in sorted_keys[: len(sorted_keys) - _MAX_RECEIPTS]:
                self._task_receipts.pop(k, None)
                self._binary_task_cache.pop(k, None)

    # ------------------------------------------------------------------ #
    # P1 Fix: Centralized tool availability verification                  #
    # ------------------------------------------------------------------ #

    def verify_tool(self, tool_name: str) -> ToolVersionInfo:
        """Verify a single tool binary is available and detect its version.

        Returns a ToolVersionInfo with the resolved path, version string,
        and verification status. Logs warnings for missing tools.
        """
        _validate_tool_name(tool_name)
        resolved = shutil.which(tool_name)
        version = self._detect_version(resolved) if resolved else None
        info = ToolVersionInfo(
            name=tool_name,
            version=version,
            path=resolved,
            verified=resolved is not None,
        )
        self._tool_versions[tool_name] = info
        if not resolved:
            logger.error(
                "Tool verification FAILED: '%s' not found in PATH or .tools/bin", tool_name
            )
        else:
            logger.info(
                "Tool verified: '%s' -> %s (version: %s)",
                tool_name,
                resolved,
                version or "unknown",
            )
        return info

    def verify_all_tools(self, tool_names: list[str] | None = None) -> dict[str, ToolVersionInfo]:
        """Verify all required tools are available before pipeline launch.

        Args:
            tool_names: List of tool names to verify. If None, verifies all allowed tools.

        Returns:
            Dict mapping tool name to ToolVersionInfo.
        """
        names = tool_names or sorted(_ALLOWED_TOOL_NAMES)
        results: dict[str, ToolVersionInfo] = {}
        missing: list[str] = []
        for name in names:
            info = self.verify_tool(name)
            results[name] = info
            if not info.verified:
                missing.append(name)
        if missing:
            logger.warning(
                "Tool verification: %d tool(s) missing: %s. "
                "Pipeline will skip modules that depend on these tools.",
                len(missing),
                ", ".join(missing),
            )
        else:
            logger.info("All %d tools verified successfully.", len(names))
        return results

    def _detect_version(self, tool_path: str) -> str | None:
        """Detect the version string of a tool binary."""
        for flag in ("-version", "--version", "-v"):
            try:
                proc = subprocess.run(  # noqa: S603
                    [tool_path, flag],
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    capture_output=True,
                    timeout=8,
                    check=False,
                    creationflags=_get_creationflags(),
                )
                output = (proc.stdout or proc.stderr or "").strip()
                if output:
                    return output.splitlines()[0][:256]
            except Exception:
                logger.debug(
                    "ProcPool: tool version detection failed for %s", tool_path, exc_info=True
                )
                continue
        return None

    @property
    def tool_versions(self) -> dict[str, ToolVersionInfo]:
        """Return detected tool versions for monitoring/drift detection."""
        return dict(self._tool_versions)

    # ------------------------------------------------------------------ #
    # warm_pool — verify tools and store base args (no persistent procs)  #
    # ------------------------------------------------------------------ #

    async def warm_pool(self, tool_name: str, base_args: list[str]) -> None:
        """Verify tool availability and store default arguments.

        This no longer spawns persistent processes. CLI tools are executed
        as one-shot subprocesses per task. The 'pool_size' parameter now
        controls the semaphore concurrency limit instead of process count.
        """
        _validate_tool_name(tool_name)
        self._base_args_map[tool_name] = base_args
        info = self.verify_tool(tool_name)
        if not info.verified:
            logger.warning(
                "warm_pool: tool '%s' not available; tasks will fail at execution time.",
                tool_name,
            )

    # ------------------------------------------------------------------ #
    # P1 Fix: Bounded one-shot subprocess execution                      #
    # ------------------------------------------------------------------ #

    async def execute_task(
        self,
        tool_name: str,
        task_data: str,
        *,
        task_id: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> str:
        """Execute a CLI tool as a one-shot subprocess.

        Spawns a fresh process for each task, bounded by the concurrency
        semaphore. Reads all stdout output (not just one line). Kills the
        entire process tree on timeout.
        """
        _validate_tool_name(tool_name)
        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": task_data})
        self._prune_stale_receipts()
        self._cap_task_receipts()
        receipt = self._task_receipts.get(stable_task_id)
        if receipt and receipt.status == "completed":
            return receipt.output

        async with self._lock:
            self._task_receipts[stable_task_id] = self._make_receipt(
                task_id=stable_task_id,
                tool_name=tool_name,
                status="running",
            )

        # P1 Fix: Acquire semaphore to bound concurrency
        async with self._semaphore:
            return await self._execute_task_inner(
                tool_name, task_data, stable_task_id, timeout_seconds
            )

    async def _execute_task_inner(
        self,
        tool_name: str,
        task_data: str,
        stable_task_id: str,
        timeout_seconds: float,
    ) -> str:
        """Inner execution logic, runs within the semaphore."""
        base_args = self._base_args_map.get(tool_name, [])
        full_args = [tool_name, *base_args, task_data]

        proc = await asyncio.create_subprocess_exec(
            *full_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=_get_creationflags(),
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=max(0.05, timeout_seconds)
            )
        except TimeoutError:
            # P1 Fix: Kill entire process tree, not just parent
            await _kill_process_tree(proc, timeout=min(5.0, timeout_seconds * 0.3))
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id,
                    tool_name,
                    "interrupted",
                    error=f"process exceeded {timeout_seconds}s budget",
                )
            raise RuntimeError(
                f"ToolExecutionError: {tool_name} exceeded time budget ({timeout_seconds}s)"
            ) from None

        output = _decode(stdout_bytes)
        stderr_text = _decode(stderr_bytes)

        if proc.returncode != 0:
            logger.error(
                "One-shot process '%s' failed (exit %d): %s",
                tool_name,
                proc.returncode,
                stderr_text[:500],
            )
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id,
                    tool_name,
                    "failed",
                    error=f"exit code {proc.returncode}: {stderr_text[:200]}",
                )
            raise RuntimeError(f"ToolExecutionError: {tool_name} failed (exit {proc.returncode})")

        async with self._lock:
            self._task_receipts[stable_task_id] = self._make_receipt(
                stable_task_id, tool_name, "completed", output=output
            )
        return output

    async def execute_task_binary(
        self,
        tool_name: str,
        task_obj: Any,
        *,
        task_id: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> Any:
        """Execute a task using binary IPC via one-shot subprocess.

        Uses length-prefixed, zstd-compressed, cloudpickle-serialized objects
        piped to stdin, with the result read from stdout.
        """
        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": repr(task_obj)})
        self._prune_stale_receipts()
        self._cap_task_receipts()
        receipt = self._task_receipts.get(stable_task_id)
        if receipt and receipt.status == "completed":
            return self._binary_task_cache.get(stable_task_id)

        async with self._lock:
            self._task_receipts[stable_task_id] = self._make_receipt(
                task_id=stable_task_id,
                tool_name=tool_name,
                status="running",
            )

        # P1 Fix: Acquire semaphore to bound concurrency
        async with self._semaphore:
            return await self._execute_task_binary_inner(
                tool_name, task_obj, stable_task_id, timeout_seconds
            )

    async def _execute_task_binary_inner(
        self,
        tool_name: str,
        task_obj: Any,
        stable_task_id: str,
        timeout_seconds: float,
    ) -> Any:
        """Inner binary execution logic, runs within the semaphore."""
        proc = await asyncio.create_subprocess_exec(
            tool_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            creationflags=_get_creationflags(),
        )
        packed_data = safe_pack(task_obj, payload_kind="proc_pool_ipc")
        input_bytes = struct.pack("!I", len(packed_data)) + packed_data

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=input_bytes), timeout=max(0.05, timeout_seconds)
            )
        except TimeoutError:
            await _kill_process_tree(proc, timeout=min(5.0, timeout_seconds * 0.3))
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id,
                    tool_name,
                    "interrupted",
                    error=f"process exceeded {timeout_seconds}s budget",
                )
            raise RuntimeError(
                f"ToolExecutionError: {tool_name} exceeded time budget ({timeout_seconds}s)"
            ) from None

        if proc.returncode != 0:
            stderr_text = _decode(stderr_bytes)
            logger.error(
                "One-shot binary process '%s' failed (exit %d): %s",
                tool_name,
                proc.returncode,
                stderr_text[:500],
            )
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id,
                    tool_name,
                    "failed",
                    error=f"exit code {proc.returncode}",
                )
            raise RuntimeError(f"ToolExecutionError: {tool_name} failed (exit {proc.returncode})")

        if len(stdout_bytes) < 4:
            raise RuntimeError(
                "ToolExecutionError: process output too short (missing length prefix)"
            )
        length = struct.unpack("!I", stdout_bytes[:4])[0]
        if length > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Payload length {length} exceeds maximum {MAX_PAYLOAD_BYTES}")
        if len(stdout_bytes) < 4 + length:
            raise RuntimeError("ToolExecutionError: process output incomplete")
        output = safe_unpack(stdout_bytes[4 : 4 + length])

        if len(self._binary_task_cache) >= _BINARY_CACHE_MAX:
            oldest_key = next(iter(self._binary_task_cache))
            del self._binary_task_cache[oldest_key]
            self._task_receipts.pop(oldest_key, None)
        self._binary_task_cache[stable_task_id] = output
        async with self._lock:
            self._task_receipts[stable_task_id] = self._make_receipt(
                stable_task_id, tool_name, "completed", output=repr(output)
            )
        return output

    # ------------------------------------------------------------------ #
    # Receipt management                                                  #
    # ------------------------------------------------------------------ #

    def recovery_receipts(self) -> dict[str, dict[str, str]]:
        """Expose task receipts so a restarted supervisor can replay interrupted work once."""
        return {
            task_id: {
                "task_id": receipt.task_id,
                "tool_name": receipt.tool_name,
                "status": receipt.status,
                "output": receipt.output,
                "error": receipt.error,
            }
            for task_id, receipt in self._task_receipts.items()
        }

    async def cleanup(self) -> None:
        """Gracefully clean up pool state.

        Since there are no persistent processes to terminate, this only
        clears internal state and receipts.
        """
        self._task_receipts.clear()
        self._binary_task_cache.clear()
        self._base_args_map.clear()
        logger.info("FrontierProcessPool cleaned up.")

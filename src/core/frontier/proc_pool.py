"""
Cyber Security Test Pipeline - Frontier Process Pool
Implements high-speed, pre-warmed worker processes for heavy CLI tools.
"""

from __future__ import annotations

import asyncio
import os
import signal
import struct
import sys
from dataclasses import dataclass
from typing import Any

from src.core.frontier.marshaller import mesh_marshal_pickle, mesh_unmarshal_pickle
from src.core.frontier.state import stable_digest
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


MAX_PAYLOAD_BYTES = 10_000_000


def _decode(value: bytes | str, encoding: str = "utf-8", errors: str = "replace") -> str:
    return value.decode(encoding, errors) if isinstance(value, bytes) else value


@dataclass
class ToolProcess:
    """A managed sub-process for a specific CLI tool."""

    name: str
    process: asyncio.subprocess.Process
    id: int
    busy: bool = False
    current_task_id: str | None = None


@dataclass
class ProcessTaskReceipt:
    """Durable-enough receipt used by the caller to decide replay after process loss."""

    task_id: str
    tool_name: str
    status: str
    output: str = ""
    error: str = ""
    timestamp: float = 0.0


class ResourceWatchdog:
    """
    Monitors process memory and CPU footprint.
    Safely terminates and recycles rogue processes exceeding constraints.
    """

    def __init__(
        self,
        pool: FrontierProcessPool,
        max_memory_mb: float = 512.0,
        check_interval_seconds: float = 2.0,
    ) -> None:
        self.pool = pool
        self.max_memory_mb = max_memory_mb
        self.check_interval_seconds = check_interval_seconds
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        while True:
            await asyncio.sleep(self.check_interval_seconds)
            if not psutil:
                continue
            try:
                # We need to take a copy of the processes list to inspect them
                async with self.pool._lock:
                    processes_copy = list(self.pool._processes)

                for p in processes_copy:
                    if p.process.returncode is not None:
                        continue
                    pid = p.process.pid
                    if not pid:
                        continue
                    try:
                        proc = psutil.Process(pid)
                        mem_info = proc.memory_info()
                        mem_mb = mem_info.rss / (1024 * 1024)
                        if mem_mb > self.max_memory_mb:
                            logger.warning(
                                "ResourceWatchdog: Process %d (PID %d) exceeded memory limit (%.1fMB > %.1fMB). Recycling.",
                                p.id,
                                pid,
                                mem_mb,
                                self.max_memory_mb,
                            )
                            # Performance #5: Do not hold the pool lock while waiting or spawning
                            try:
                                if sys.platform != "win32":
                                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                                else:
                                    p.process.terminate()
                            except Exception:
                                p.process.kill()

                            # Wait for termination outside the lock-heavy loop if possible,
                            # but here p is just a dataclass from our copy.
                            await p.process.wait()

                            # Respawn a new one in its place
                            spawn_kwargs: dict[str, Any] = {
                                "stdin": asyncio.subprocess.PIPE,
                                "stdout": asyncio.subprocess.PIPE,
                                "stderr": asyncio.subprocess.PIPE,
                            }
                            if sys.platform != "win32":
                                spawn_kwargs["preexec_fn"] = os.setpgrp
                            else:
                                import subprocess

                                spawn_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

                            base_args = self.pool._base_args_map.get(p.name, [])
                            new_proc = await asyncio.create_subprocess_exec(
                                p.name, *base_args, **spawn_kwargs
                            )

                            # Safely replace process in the REAL pool
                            async with self.pool._lock:
                                # Find the actual object in self.pool._processes
                                for real_p in self.pool._processes:
                                    if real_p.id == p.id:
                                        real_p.process = new_proc
                                        real_p.busy = False
                                        real_p.current_task_id = None
                                        break
                    except psutil.NoSuchProcess:
                        pass
            except Exception as e:
                logger.error("ResourceWatchdog monitor error: %s", e)


_STALE_TTL = 300
_BINARY_CACHE_MAX = 1000


class FrontierProcessPool:
    """
    Managed Execution Pool.
    Maintains pre-warmed instances of security tools to eliminate process startup latency.
    """

    def __init__(self, pool_size: int | None = None, max_memory_mb: float = 512.0) -> None:
        # Fix Audit #198: Adapt pool size to CPU cores
        if pool_size is None:
            cpu_count = os.cpu_count() or 2
            self.pool_size = min(4, cpu_count)
        else:
            self.pool_size = pool_size

        self._processes: list[ToolProcess] = []
        self._lock = asyncio.Lock()
        self._task_receipts: dict[str, ProcessTaskReceipt] = {}
        self._last_receipt_prune: float = 0.0
        self._base_args_map: dict[str, list[str]] = {}
        self._binary_task_cache: dict[str, Any] = {}
        self._watchdog = ResourceWatchdog(self, max_memory_mb=max_memory_mb)
        self._watchdog_started = False

    def _ensure_watchdog_started(self) -> None:
        if self._watchdog_started:
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self._watchdog.start()
        self._watchdog_started = True

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
            timestamp=asyncio.get_event_loop().time(),
        )

    def _prune_stale_receipts(self) -> None:
        now = asyncio.get_event_loop().time()
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

    async def warm_pool(self, tool_name: str, base_args: list[str]) -> None:
        """Spawn initial process set."""
        self._ensure_watchdog_started()
        self._base_args_map[tool_name] = base_args
        # Fix Audit #14: Windows compatibility for preexec_fn
        spawn_kwargs: dict[str, Any] = {
            "stdin": asyncio.subprocess.PIPE,
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
        }
        if sys.platform != "win32":
            spawn_kwargs["preexec_fn"] = os.setpgrp
        else:
            # On Windows, we can use creationflags to achieve similar process group isolation
            # Fix #210: creationflags needs to be the actual subprocess constant
            import subprocess

            spawn_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        for i in range(self.pool_size):
            proc = await asyncio.create_subprocess_exec(tool_name, *base_args, **spawn_kwargs)
            self._processes.append(ToolProcess(tool_name, proc, i))
        logger.info("Warmed Frontier Pool for '%s' (Size: %d)", tool_name, self.pool_size)

    async def acquire_process(self, task_id: str | None = None) -> ToolProcess | None:
        """Find an idle process in the pool."""
        async with self._lock:
            for p in self._processes:
                if not p.busy:
                    p.busy = True
                    p.current_task_id = task_id
                    return p
        return None

    async def release_process(self, p_id: int) -> None:
        """Mark a process as idle."""
        async with self._lock:
            for p in self._processes:
                if p.id == p_id:
                    p.busy = False
                    p.current_task_id = None
                    break

    async def execute_task(
        self,
        tool_name: str,
        task_data: str,
        *,
        task_id: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> str:
        """
        Execute a task using a pooled process.
        Uses Pipes for zero-disk IPC.
        """
        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": task_data})
        self._prune_stale_receipts()
        receipt = self._task_receipts.get(stable_task_id)
        if receipt and receipt.status == "completed":
            return receipt.output

        async with self._lock:
            self._task_receipts[stable_task_id] = self._make_receipt(
                task_id=stable_task_id,
                tool_name=tool_name,
                status="running",
            )

        p = await self.acquire_process(stable_task_id)
        if not p:
            # Fallback to one-off process if pool is full
            # Fix Audit #83: Capture stderr and capture diagnostics
            proc = await asyncio.create_subprocess_exec(
                tool_name, task_data, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=max(0.05, timeout_seconds)
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "interrupted",
                        error=f"process exceeded {timeout_seconds}s budget",
                    )
                raise RuntimeError(
                    f"ToolExecutionError: One-off process {tool_name} exceeded time budget"
                ) from None
            if proc.returncode != 0:
                logger.error(
                    "One-off process '%s' failed (exit %d): %s",
                    tool_name,
                    proc.returncode,
                    _decode(stderr),
                )
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "failed",
                        error=f"exit code {proc.returncode}",
                    )
                raise RuntimeError(
                    f"ToolExecutionError: One-off process {tool_name} failed (exit {proc.returncode})"
                )
            output = _decode(stdout)
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id, tool_name, "completed", output=output
                )
            return output

        try:
            # Fix #209: Check if process is dead using returncode instead of stdin.is_closing()
            if p.process.returncode is not None:
                logger.warning("Process %d is dead, cannot execute task", p.id)
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "interrupted",
                        error="pooled process already exited",
                    )
                raise RuntimeError(f"ToolExecutionError: pooled process {tool_name} already exited")

            if p.process.stdin is None or p.process.stdout is None:
                logger.error("Process %d missing stdin/stdout", p.id)
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "interrupted",
                        error="pooled process missing pipes",
                    )
                raise RuntimeError(f"ToolExecutionError: pooled process {tool_name} missing pipes")

            # Send task to pre-warmed process stdin
            p.process.stdin.write(f"{task_data}\n".encode())
            await p.process.stdin.drain()

            # Read response (assuming tool supports JSON-RPC line-by-line)
            try:
                line = await asyncio.wait_for(
                    p.process.stdout.readline(), timeout=max(0.05, timeout_seconds)
                )
            except TimeoutError:
                if p.current_task_id:
                    async with self._lock:
                        self._task_receipts[p.current_task_id] = self._make_receipt(
                            p.current_task_id,
                            tool_name,
                            "interrupted",
                            error=f"process exceeded {timeout_seconds}s budget",
                        )
                if sys.platform != "win32" and p.process.pid:
                    os.killpg(os.getpgid(p.process.pid), signal.SIGTERM)
                else:
                    p.process.terminate()
                await p.process.wait()
                raise RuntimeError(
                    f"ToolExecutionError: pooled process {tool_name} exceeded time budget"
                ) from None
            output = _decode(line)
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id, tool_name, "completed", output=output
                )
            return output
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error("Process %d IPC failure: %s", p.id, e)
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id, tool_name, "interrupted", error=str(e)
                )
            return ""
        finally:
            await self.release_process(p.id)

    async def execute_task_binary(
        self,
        tool_name: str,
        task_obj: Any,
        *,
        task_id: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> Any:
        """
        Execute a task using a pooled process using binary IPC.
        Uses length-prefixed, zstd-compressed, cloudpickle-serialized objects over Pipes.
        """
        stable_task_id = task_id or stable_digest({"tool": tool_name, "task": repr(task_obj)})
        self._prune_stale_receipts()
        receipt = self._task_receipts.get(stable_task_id)
        if receipt and receipt.status == "completed":
            return self._binary_task_cache.get(stable_task_id)

        async with self._lock:
            self._task_receipts[stable_task_id] = self._make_receipt(
                task_id=stable_task_id,
                tool_name=tool_name,
                status="running",
            )

        p = await self.acquire_process(stable_task_id)
        if not p:
            # Fallback to one-off process if pool is full
            proc = await asyncio.create_subprocess_exec(
                tool_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE,
            )
            packed_data = mesh_marshal_pickle(task_obj)
            try:
                input_bytes = struct.pack("!I", len(packed_data)) + packed_data
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=input_bytes), timeout=max(0.05, timeout_seconds)
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "interrupted",
                        error=f"process exceeded {timeout_seconds}s budget",
                    )
                raise RuntimeError(
                    f"ToolExecutionError: One-off process {tool_name} exceeded time budget"
                ) from None
            if proc.returncode != 0:
                logger.error(
                    "One-off process '%s' failed (exit %d): %s",
                    tool_name,
                    proc.returncode,
                    _decode(stderr),
                )
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "failed",
                        error=f"exit code {proc.returncode}",
                    )
                raise RuntimeError(
                    f"ToolExecutionError: One-off process {tool_name} failed (exit {proc.returncode})"
                )
            if len(stdout) < 4:
                raise RuntimeError(
                    "ToolExecutionError: One-off process output too short (missing length prefix)"
                )
            length = struct.unpack("!I", stdout[:4])[0]
            if length > MAX_PAYLOAD_BYTES:
                raise ValueError(f"Payload length {length} exceeds maximum {MAX_PAYLOAD_BYTES}")
            if len(stdout) < 4 + length:
                raise RuntimeError("ToolExecutionError: One-off process output incomplete")
            output = mesh_unmarshal_pickle(stdout[4 : 4 + length])
            if len(self._binary_task_cache) >= _BINARY_CACHE_MAX:
                oldest_key = next(iter(self._binary_task_cache))
                del self._binary_task_cache[oldest_key]
            self._binary_task_cache[stable_task_id] = output
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id, tool_name, "completed", output=repr(output)
                )
            return output

        try:
            if p.process.returncode is not None:
                logger.warning("Process %d is dead, cannot execute task", p.id)
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "interrupted",
                        error="pooled process already exited",
                    )
                raise RuntimeError(f"ToolExecutionError: pooled process {tool_name} already exited")

            if p.process.stdin is None or p.process.stdout is None:
                logger.error("Process %d missing stdin/stdout", p.id)
                async with self._lock:
                    self._task_receipts[stable_task_id] = self._make_receipt(
                        stable_task_id,
                        tool_name,
                        "interrupted",
                        error="pooled process missing pipes",
                    )
                raise RuntimeError(f"ToolExecutionError: pooled process {tool_name} missing pipes")

            packed_data = mesh_marshal_pickle(task_obj)
            p.process.stdin.write(struct.pack("!I", len(packed_data)) + packed_data)
            await p.process.stdin.drain()

            try:
                length_bytes = await asyncio.wait_for(
                    p.process.stdout.readexactly(4), timeout=max(0.05, timeout_seconds)
                )
                length = struct.unpack("!I", length_bytes)[0]
                if length > MAX_PAYLOAD_BYTES:
                    raise ValueError(f"Payload length {length} exceeds maximum {MAX_PAYLOAD_BYTES}")
                payload_bytes = await asyncio.wait_for(
                    p.process.stdout.readexactly(length), timeout=max(0.05, timeout_seconds)
                )
                output = mesh_unmarshal_pickle(payload_bytes)
            except TimeoutError:
                if p.current_task_id:
                    async with self._lock:
                        self._task_receipts[p.current_task_id] = self._make_receipt(
                            p.current_task_id,
                            tool_name,
                            "interrupted",
                            error=f"process exceeded {timeout_seconds}s budget",
                        )
                if sys.platform != "win32" and p.process.pid:
                    os.killpg(os.getpgid(p.process.pid), signal.SIGTERM)
                else:
                    p.process.terminate()
                await p.process.wait()
                raise RuntimeError(
                    f"ToolExecutionError: pooled process {tool_name} exceeded time budget"
                ) from None
            if len(self._binary_task_cache) >= _BINARY_CACHE_MAX:
                oldest_key = next(iter(self._binary_task_cache))
                del self._binary_task_cache[oldest_key]
            self._binary_task_cache[stable_task_id] = output
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id, tool_name, "completed", output=repr(output)
                )
            return output
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error("Process %d IPC failure: %s", p.id, e)
            async with self._lock:
                self._task_receipts[stable_task_id] = self._make_receipt(
                    stable_task_id, tool_name, "interrupted", error=str(e)
                )
            return None
        finally:
            await self.release_process(p.id)

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
        """Gracefully terminate the pool."""
        if hasattr(self, "_watchdog") and self._watchdog:
            await self._watchdog.stop()
            self._watchdog_started = False
        for p in self._processes:
            try:
                if p.current_task_id:
                    async with self._lock:
                        self._task_receipts[p.current_task_id] = self._make_receipt(
                            p.current_task_id,
                            p.name,
                            "interrupted",
                            error="process pool cleanup before task completion",
                        )
                # Fix Audit #15: SIGTERM compatibility for Windows
                if sys.platform != "win32":
                    os.killpg(os.getpgid(p.process.pid), signal.SIGTERM)
                else:
                    p.process.terminate()
                await p.process.wait()
            except Exception as e:
                logger.debug("Failed to terminate process %d: %s", p.id, e)
        self._processes = []

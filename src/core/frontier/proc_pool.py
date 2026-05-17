"""
Cyber Security Test Pipeline - Frontier Process Pool
Implements high-speed, pre-warmed worker processes for heavy CLI tools.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from dataclasses import dataclass
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


@dataclass
class ToolProcess:
    """A managed sub-process for a specific CLI tool."""

    name: str
    process: asyncio.subprocess.Process
    id: int
    busy: bool = False


class FrontierProcessPool:
    """
    Managed Execution Pool.
    Maintains pre-warmed instances of security tools to eliminate process startup latency.
    """

    def __init__(self, pool_size: int | None = None) -> None:
        # Fix Audit #198: Adapt pool size to CPU cores
        if pool_size is None:
            cpu_count = os.cpu_count() or 2
            self.pool_size = min(4, cpu_count)
        else:
            self.pool_size = pool_size

        self._processes: list[ToolProcess] = []
        self._lock = asyncio.Lock()

    async def warm_pool(self, tool_name: str, base_args: list[str]) -> None:
        """Spawn initial process set."""
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

    async def acquire_process(self) -> ToolProcess | None:
        """Find an idle process in the pool."""
        async with self._lock:
            for p in self._processes:
                if not p.busy:
                    p.busy = True
                    return p
        return None

    async def release_process(self, p_id: int) -> None:
        """Mark a process as idle."""
        async with self._lock:
            for p in self._processes:
                if p.id == p_id:
                    p.busy = False
                    break

    async def execute_task(self, tool_name: str, task_data: str) -> str:
        """
        Execute a task using a pooled process.
        Uses Pipes for zero-disk IPC.
        """
        p = await self.acquire_process()
        if not p:
            # Fallback to one-off process if pool is full
            # Fix Audit #83: Capture stderr and capture diagnostics
            proc = await asyncio.create_subprocess_exec(
                tool_name, task_data, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error(
                    "One-off process '%s' failed (exit %d): %s",
                    tool_name,
                    proc.returncode,
                    stderr.decode(),
                )
                # Fix #211: Raise exception instead of returning partial output
                raise RuntimeError(
                    f"ToolExecutionError: One-off process {tool_name} failed (exit {proc.returncode})"
                )
            return stdout.decode()

        try:
            # Fix #209: Check if process is dead using returncode instead of stdin.is_closing()
            if p.process.returncode is not None:
                logger.warning("Process %d is dead, cannot execute task", p.id)
                return ""

            if p.process.stdin is None or p.process.stdout is None:
                logger.error("Process %d missing stdin/stdout", p.id)
                return ""

            # Send task to pre-warmed process stdin
            p.process.stdin.write(f"{task_data}\n".encode())
            await p.process.stdin.drain()

            # Read response (assuming tool supports JSON-RPC line-by-line)
            line = await p.process.stdout.readline()
            return line.decode()
        except (BrokenPipeError, ConnectionResetError) as e:
            logger.error("Process %d IPC failure: %s", p.id, e)
            return ""
        finally:
            await self.release_process(p.id)

    async def cleanup(self) -> None:
        """Gracefully terminate the pool."""
        for p in self._processes:
            try:
                # Fix Audit #15: SIGTERM compatibility for Windows
                if sys.platform != "win32":
                    os.killpg(os.getpgid(p.process.pid), signal.SIGTERM)
                else:
                    p.process.terminate()
            except Exception as e:
                logger.debug("Failed to terminate process %d: %s", p.id, e)
        self._processes = []

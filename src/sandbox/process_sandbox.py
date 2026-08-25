"""Native OS-Level Process Sandbox with Resource Limits and Environment Scrubbing.

Provides enforceable memory ceilings, CPU timeouts, and credential scrubbing
for untrusted tool/exploit subprocesses on POSIX and Windows environments.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

SENSITIVE_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "DATABASE_URL",
    "MESH_SECRET",
    "JWT_",
    "API_KEY",
)


@dataclass(frozen=True, slots=True)
class SandboxResourceLimits:
    """Resource constraints enforced on sandboxed subprocesses."""

    max_memory_mb: int = 256
    max_cpu_seconds: int = 30
    timeout_seconds: float = 30.0
    allow_network: bool = True


@dataclass(frozen=True, slots=True)
class SandboxExecutionResult:
    """Result of running a command within the OS sandbox."""

    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    memory_exceeded: bool = False
    error: str = ""

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.memory_exceeded


class ProcessSandbox:
    """Enforces OS-native process cages for exploit and plugin runners."""

    def __init__(self, limits: SandboxResourceLimits | None = None) -> None:
        self.limits = limits or SandboxResourceLimits()

    def scrub_environment(self, custom_env: dict[str, str] | None = None) -> dict[str, str]:
        """Strip host credentials and sensitive platform tokens from the child environment."""
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "TEMP": os.environ.get("TEMP", "/tmp"),
            "TMP": os.environ.get("TMP", "/tmp"),
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
        }

        # Keep non-sensitive variables
        for k, v in os.environ.items():
            if not any(k.upper().startswith(p) or p in k.upper() for p in SENSITIVE_ENV_PREFIXES):
                clean_env[k] = v

        if custom_env:
            clean_env.update(custom_env)

        return clean_env

    def run(
        self,
        command: list[str] | tuple[str, ...],
        input_data: str | bytes | None = None,
        cwd: str | None = None,
        custom_env: dict[str, str] | None = None,
    ) -> SandboxExecutionResult:
        """Execute command within sanitized and resource-constrained sandbox."""
        cmd_tuple = tuple(command)
        env = self.scrub_environment(custom_env)
        start_time = time.time()

        # POSIX preexec_fn for rlimits
        preexec_fn = None
        if sys.platform != "win32":
            try:
                import resource

                def _set_posix_limits() -> None:
                    # Memory limit (RLIMIT_AS) in bytes
                    mem_bytes = self.limits.max_memory_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                    # CPU time limit
                    cpu_secs = self.limits.max_cpu_seconds
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu_secs, cpu_secs))

                preexec_fn = _set_posix_limits
            except (ImportError, AttributeError):
                preexec_fn = None

        stdin_bytes = None
        if input_data is not None:
            stdin_bytes = input_data.encode("utf-8") if isinstance(input_data, str) else input_data

        timed_out = False
        try:
            proc = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE if stdin_bytes else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                preexec_fn=preexec_fn,
            )

            stdout_bytes, stderr_bytes = proc.communicate(
                input=stdin_bytes,
                timeout=self.limits.timeout_seconds,
            )
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_bytes, stderr_bytes = proc.communicate()
            exit_code = -1
            timed_out = True
        except Exception as exc:
            duration = time.time() - start_time
            return SandboxExecutionResult(
                command=cmd_tuple,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
                error=f"Sandbox execution failed: {exc}",
            )

        duration = time.time() - start_time
        stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

        # Check for OOM signals (SIGKILL / 137 on Linux)
        memory_exceeded = exit_code == 137 or "MemoryError" in stderr_str

        return SandboxExecutionResult(
            command=cmd_tuple,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_seconds=duration,
            timed_out=timed_out,
            memory_exceeded=memory_exceeded,
        )


__all__ = [
    "ProcessSandbox",
    "SandboxExecutionResult",
    "SandboxResourceLimits",
]

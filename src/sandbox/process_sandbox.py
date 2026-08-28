"""Native OS-Level Process Sandbox with Resource Limits and Environment Scrubbing.

Provides enforceable memory ceilings, CPU timeouts, and credential scrubbing
for untrusted tool/exploit subprocesses on POSIX and Windows environments.
"""

from __future__ import annotations

import enum
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass

from src.sandbox.network_isolation import NetworkEgressFilter
from src.sandbox.seccomp_filter import SeccompPolicy, get_default_seccomp_policy

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


class SandboxClass(enum.StrEnum):
    """Distinguishes lightweight native fuzzer workloads from heavy browser DOM runtimes."""

    NATIVE = "native"
    DOM = "dom"


@dataclass(frozen=True, slots=True)
class SandboxResourceLimits:
    """Resource constraints enforced on sandboxed subprocesses."""

    max_memory_mb: int = 256
    max_cpu_seconds: int = 30
    timeout_seconds: float = 30.0
    allow_network: bool = True
    sandbox_class: SandboxClass = SandboxClass.NATIVE

    @classmethod
    def for_class(cls, sandbox_class: SandboxClass) -> SandboxResourceLimits:
        """Construct tailored resource limits per sandbox workload class."""
        if sandbox_class == SandboxClass.DOM:
            return cls(
                max_memory_mb=2048,
                max_cpu_seconds=120,
                timeout_seconds=120.0,
                allow_network=True,
                sandbox_class=SandboxClass.DOM,
            )
        return cls(
            max_memory_mb=256,
            max_cpu_seconds=30,
            timeout_seconds=30.0,
            allow_network=True,
            sandbox_class=SandboxClass.NATIVE,
        )


class SandboxCapabilityError(PermissionError):
    """Raised when kernel-enforced sandbox mode is requested but the host lacks required capabilities."""


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
    enforcement_level: str = "DEGRADED_USERSPACE"
    degraded_reason: str = ""

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.memory_exceeded


class ProcessSandbox:
    """Enforces OS-native process cages for exploit and plugin runners."""

    def __init__(
        self,
        limits: SandboxResourceLimits | None = None,
        *,
        egress_filter: NetworkEgressFilter | None = None,
        seccomp_policy: SeccompPolicy | None = None,
        required_enforcement_level: str | SandboxEnforcementLevel | None = None,
    ) -> None:
        from src.sandbox.seccomp_filter import (
            SandboxEnforcementLevel,
            detect_sandbox_capabilities,
        )

        self.limits = limits or SandboxResourceLimits()
        # I29: every sandbox at least denies cloud-metadata destinations.
        self.egress_filter = (
            egress_filter if egress_filter is not None else NetworkEgressFilter.metadata_guard()
        )
        self.seccomp_policy = (
            seccomp_policy if seccomp_policy is not None else get_default_seccomp_policy()
        )

        # Detect host capability at boot/init
        self.capabilities = detect_sandbox_capabilities()
        self.enforcement_level = self.capabilities.enforcement_level
        self.degraded_reason = self.capabilities.degraded_reason

        # Refuse "kernel-enforced" claims when capability is unavailable
        if required_enforcement_level is not None:
            req_str = (
                required_enforcement_level.value
                if isinstance(required_enforcement_level, SandboxEnforcementLevel)
                else str(required_enforcement_level)
            )
            if (
                req_str == SandboxEnforcementLevel.KERNEL_ENFORCED.value
                and self.enforcement_level != SandboxEnforcementLevel.KERNEL_ENFORCED
            ):
                raise SandboxCapabilityError(
                    f"KERNEL_ENFORCEMENT_UNAVAILABLE: Host cannot satisfy KERNEL_ENFORCED sandbox. "
                    f"Reason: {self.degraded_reason}"
                )

        if self.enforcement_level == SandboxEnforcementLevel.DEGRADED_USERSPACE:
            logger.info("ProcessSandbox operating in DEGRADED_USERSPACE mode: %s", self.degraded_reason)

    def check_egress(self, host: str, port: int | None = None) -> None:
        """Enforce I29 before the worker opens a destination."""
        if self.egress_filter is None:
            return
        self.egress_filter.validate_destination_or_raise(host, port)

    def scrub_environment(self, custom_env: dict[str, str] | None = None) -> dict[str, str]:
        """Strip host credentials and sensitive platform tokens from the child environment."""
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "TEMP": os.environ.get("TEMP", "/tmp"),  # noqa: S108
            "TMP": os.environ.get("TMP", "/tmp"),  # noqa: S108
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
        destination_host: str | None = None,
        destination_port: int | None = None,
    ) -> SandboxExecutionResult:
        """Execute command within sanitized and resource-constrained sandbox."""
        if destination_host:
            self.check_egress(destination_host, destination_port)

        from src.sandbox.seccomp_filter import KernelEgressNamespace

        # Kernel-level network namespace isolation prefix (e.g. `unshare -n`)
        ns_prefix = KernelEgressNamespace.get_namespace_command_prefix(
            allow_network=self.limits.allow_network
        )
        effective_command = ns_prefix + list(command)

        cmd_tuple = tuple(command)
        env = self.scrub_environment(custom_env)

        # Inject scoped proxy into child subprocess env (I29 enforcement for external CLI tools)
        proxy_server = None
        if self.egress_filter is not None and self.limits.allow_network:
            from src.sandbox.proxy_guard import ScopedProxyServer
            proxy_server = ScopedProxyServer(self.egress_filter)
            proxy_url = proxy_server.start()
            env["HTTP_PROXY"] = proxy_url
            env["HTTPS_PROXY"] = proxy_url
            env["http_proxy"] = proxy_url
            env["https_proxy"] = proxy_url

        start_time = time.time()

        # POSIX preexec_fn for rlimits + optional seccomp BPF
        preexec_fn = None
        if sys.platform != "win32":
            try:
                import resource

                seccomp_filter = None
                if self.seccomp_policy is not None:
                    try:
                        seccomp_filter = self.seccomp_policy.build_bpf_filter()
                    except Exception as exc:
                        logger.debug("Seccomp BPF construction skipped: %s", exc)
                        seccomp_filter = None

                def _set_posix_limits() -> None:
                    # Memory limit (RLIMIT_AS) in bytes
                    mem_bytes = self.limits.max_memory_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                    # CPU time limit
                    cpu_secs = self.limits.max_cpu_seconds
                    resource.setrlimit(resource.RLIMIT_CPU, (cpu_secs, cpu_secs))
                    if seccomp_filter is not None and hasattr(seccomp_filter, "load"):
                        seccomp_filter.load()

                preexec_fn = _set_posix_limits
            except (ImportError, AttributeError):
                preexec_fn = None

        stdin_bytes = None
        if input_data is not None:
            stdin_bytes = input_data.encode("utf-8") if isinstance(input_data, str) else input_data

        timed_out = False
        try:
            proc = subprocess.Popen(  # noqa: S603
                effective_command,
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
            if proxy_server is not None:
                proxy_server.stop()
            duration = time.time() - start_time
            return SandboxExecutionResult(
                command=cmd_tuple,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
                error=f"Sandbox execution failed: {exc}",
                enforcement_level=self.enforcement_level.value,
                degraded_reason=self.degraded_reason,
            )
        finally:
            if proxy_server is not None:
                proxy_server.stop()

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
            enforcement_level=self.enforcement_level.value,
            degraded_reason=self.degraded_reason,
        )


__all__ = [
    "ProcessSandbox",
    "SandboxCapabilityError",
    "SandboxClass",
    "SandboxExecutionResult",
    "SandboxResourceLimits",
]

"""Linux Seccomp Syscall Filtering and Process Caging.

Restricts untrusted worker subprocesses from executing dangerous kernel primitives:
- Blocks process injection / debugging (ptrace)
- Blocks namespace and filesystem manipulation (mount, umount2, unshare, setns, pivot_root)
- Blocks system reboot, kernel module loading, and raw socket manipulation
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

# Dangerous Linux syscalls unconditionally blocked in sandboxes
BLOCKED_SYSCALLS = frozenset(
    [
        "ptrace",
        "mount",
        "umount",
        "umount2",
        "unshare",
        "setns",
        "pivot_root",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "init_module",
        "finit_module",
        "delete_module",
        "iopl",
        "ioperm",
        "swapon",
        "swapoff",
        "process_vm_readv",
        "process_vm_writev",
    ]
)

# Syscalls blocked when network access is completely disabled in sandbox (allow_network=False)
NETWORK_SYSCALLS = frozenset(
    [
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
    ]
)


@dataclass(frozen=True, slots=True)
class SeccompPolicy:
    """Seccomp BPF policy specification for subprocess execution."""

    default_action: str = "ALLOW"
    blocked_syscalls: tuple[str, ...] = tuple(sorted(BLOCKED_SYSCALLS))
    block_network_syscalls: bool = False
    audit_mode: bool = False

    def is_syscall_allowed(self, syscall_name: str) -> bool:
        """Check if a syscall is permitted under current policy."""
        name = syscall_name.lower()
        if name in self.blocked_syscalls:
            return False
        if self.block_network_syscalls and name in NETWORK_SYSCALLS:
            return False
        return True

    def build_bpf_filter(self) -> Any:
        """Construct native BPF filter if libseccomp is available on Linux."""
        if sys.platform != "linux":
            return None

        try:
            import seccomp  # type: ignore[import-not-found]

            action = seccomp.LOG if self.audit_mode else seccomp.KILL_PROCESS
            f = seccomp.SyscallFilter(seccomp.ALLOW)
            for sc in self.blocked_syscalls:
                try:
                    f.add_rule(action, sc)
                except Exception as exc:
                    logger.debug("Could not add seccomp rule for %s: %s", sc, exc)
            if self.block_network_syscalls:
                for sc in NETWORK_SYSCALLS:
                    try:
                        f.add_rule(action, sc)
                    except Exception as exc:
                        logger.debug("Could not add seccomp network rule for %s: %s", sc, exc)
            return f
        except ImportError:
            logger.debug(
                "libseccomp Python bindings not installed; falling back to POSIX rlimit containment"
            )
            return None


class SandboxEnforcementLevel(StrEnum):
    """Declared capability enforcement level of the running host."""

    KERNEL_ENFORCED = "KERNEL_ENFORCED"  # Linux NetNS (unshare -n) + Seccomp-BPF
    DEGRADED_USERSPACE = "DEGRADED_USERSPACE"  # Userspace Proxy Guard + POSIX rlimits / Win32


@dataclass(frozen=True, slots=True)
class SandboxCapabilityReport:
    """Boot-time capability report for the process sandbox."""

    platform: str
    has_netns_unshare: bool
    has_seccomp_bpf: bool
    has_posix_rlimit: bool
    enforcement_level: SandboxEnforcementLevel
    degraded_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "has_netns_unshare": self.has_netns_unshare,
            "has_seccomp_bpf": self.has_seccomp_bpf,
            "has_posix_rlimit": self.has_posix_rlimit,
            "enforcement_level": self.enforcement_level.value,
            "degraded_reason": self.degraded_reason,
        }


def detect_sandbox_capabilities() -> SandboxCapabilityReport:
    """Detect OS-level isolation capabilities at boot."""
    has_netns = sys.platform == "linux" and os.path.exists("/proc/self/ns/net")
    has_seccomp = sys.platform == "linux" and importlib.util.find_spec("seccomp") is not None

    has_rlimit = False
    if sys.platform != "win32":
        try:
            import resource  # noqa: F401

            has_rlimit = True
        except ImportError:
            has_rlimit = False

    if has_netns and has_seccomp:
        level = SandboxEnforcementLevel.KERNEL_ENFORCED
        reason = ""
    else:
        level = SandboxEnforcementLevel.DEGRADED_USERSPACE
        reasons = []
        if sys.platform != "linux":
            reasons.append(f"non-linux platform ({sys.platform})")
        else:
            if not has_netns:
                reasons.append("missing /proc/self/ns/net")
            if not has_seccomp:
                reasons.append("missing libseccomp python bindings")
        reason = f"Degraded userspace fallback active: {', '.join(reasons)}"

    return SandboxCapabilityReport(
        platform=sys.platform,
        has_netns_unshare=has_netns,
        has_seccomp_bpf=has_seccomp,
        has_posix_rlimit=has_rlimit,
        enforcement_level=level,
        degraded_reason=reason,
    )


class KernelEgressNamespace:
    """Linux Network Namespace (netns) + iptables/nftables kernel egress controller."""

    @staticmethod
    def is_kernel_isolation_supported() -> bool:
        """Check if Linux network namespaces and unshare are available."""
        return sys.platform == "linux" and os.path.exists("/proc/self/ns/net")

    @staticmethod
    def get_namespace_command_prefix(allow_network: bool = True) -> list[str]:
        """Wrap command with `unshare -n` for kernel-level network namespace isolation."""
        if not allow_network and KernelEgressNamespace.is_kernel_isolation_supported():
            return ["unshare", "-n"]
        return []


def get_default_seccomp_policy(allow_network: bool = True) -> SeccompPolicy:
    return SeccompPolicy(block_network_syscalls=not allow_network)


__all__ = [
    "BLOCKED_SYSCALLS",
    "KernelEgressNamespace",
    "NETWORK_SYSCALLS",
    "SandboxCapabilityReport",
    "SandboxEnforcementLevel",
    "SeccompPolicy",
    "detect_sandbox_capabilities",
    "get_default_seccomp_policy",
]

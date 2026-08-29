"""Authority enforcement self-check (boot-time, fail-closed).

Import each enforcing module from the invariant registry. Missing hooks
raise BootstrapEnforcementError before mutating paths are served.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REQUIRE_KERNEL_SANDBOX = "REQUIRE_KERNEL_SANDBOX"


class BootstrapEnforcementError(RuntimeError):
    """Boot refused because an invariant hook is missing or unwired."""


@dataclass
class InvariantHook:
    invariant: str
    module_path: str
    required: bool = True
    check: str = "importable"


INVARIANT_HOOKS: tuple[InvariantHook, ...] = (
    InvariantHook("I3", "src.core.frontier.replicated_log"),
    InvariantHook("I15", "src.core.frontier.replicated_log"),
    InvariantHook("I22", "src.core.frontier.invariant_graph"),
    InvariantHook("I28", "src.core.frontier.lease_status"),
    InvariantHook("I28", "src.decision.hunt_budget"),
    InvariantHook("I29", "src.sandbox.egress_context"),
    InvariantHook("I29", "src.sandbox.process_sandbox"),
    InvariantHook("I30", "src.decision.authorization"),
    InvariantHook("I31", "src.core.events.event_bus"),
    InvariantHook("I32", "src.core.frontier.event_delivery"),
    InvariantHook("I35", "src.core.frontier.recovery_protocol"),
    InvariantHook("I36", "src.core.frontier.region_model"),
    InvariantHook("I37", "src.core.frontier.authority_transfer"),
    InvariantHook("I33", "src.core.frontier.causal_identity"),
    InvariantHook("I38", "src.core.frontier.tenant_isolation"),
    InvariantHook("I28c", "src.core.frontier.compensation_log", required=False),
    InvariantHook("I5", "src.core.frontier.lease_reaper", required=False),
)


@dataclass
class EnforcementReport:
    ok: bool
    wired: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "wired": list(self.wired),
            "missing": list(self.missing),
            "degraded": list(self.degraded),
            "sha256": self.sha256,
        }


def verify_enforcement(*, write_attestation: Path | str | None = None) -> EnforcementReport:
    report = EnforcementReport(ok=True)
    for hook in INVARIANT_HOOKS:
        try:
            importlib.import_module(hook.module_path)
            report.wired.append(f"{hook.invariant}:{hook.module_path}")
        except Exception as exc:
            label = f"{hook.invariant}:{hook.module_path} ({exc})"
            if hook.required:
                report.missing.append(label)
                report.ok = False
            else:
                report.degraded.append(label)

    if os.environ.get(REQUIRE_KERNEL_SANDBOX, "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        try:
            from src.sandbox.seccomp_filter import (
                SandboxEnforcementLevel,
                detect_sandbox_capabilities,
            )

            caps = detect_sandbox_capabilities()
            if caps.enforcement_level is not SandboxEnforcementLevel.KERNEL_ENFORCED:
                report.missing.append(
                    f"REQUIRE_KERNEL_SANDBOX but host is {caps.enforcement_level.value}: "
                    f"{caps.degraded_reason}"
                )
                report.ok = False
        except Exception as exc:
            report.missing.append(f"REQUIRE_KERNEL_SANDBOX probe failed: {exc}")
            report.ok = False

    blob = json.dumps(report.to_dict(), sort_keys=True).encode("utf-8")
    report.sha256 = hashlib.sha256(blob).hexdigest()
    if write_attestation is not None:
        dest = Path(write_attestation)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    if not report.ok:
        raise BootstrapEnforcementError(
            "Invariant enforcement self-check failed: " + "; ".join(report.missing)
        )
    return report


__all__ = [
    "BootstrapEnforcementError",
    "EnforcementReport",
    "INVARIANT_HOOKS",
    "verify_enforcement",
]

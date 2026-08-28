"""Declarative Ixx → module wiring map. Boot calls verify() for attestation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.bootstrap.enforcement_check import (
    INVARIANT_HOOKS,
    BootstrapEnforcementError,
    EnforcementReport,
    verify_enforcement,
)


def verify(write_attestation: Path | str | None = None) -> EnforcementReport:
    return verify_enforcement(write_attestation=write_attestation)


def as_dict() -> dict[str, Any]:
    return {
        hook.invariant: {
            "module_path": hook.module_path,
            "required": hook.required,
            "check": hook.check,
        }
        for hook in INVARIANT_HOOKS
    }


__all__ = [
    "BootstrapEnforcementError",
    "INVARIANT_HOOKS",
    "as_dict",
    "verify",
]

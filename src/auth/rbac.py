"""RBAC helpers on top of the capability matrix."""

from __future__ import annotations

from src.auth.capabilities import Capability, can, missing_capabilities
from src.auth.session import Session


class PermissionError(Exception):
    def __init__(self, capability: str, role: str) -> None:
        super().__init__(f"role {role!r} missing {capability}")
        self.capability = capability
        self.role = role


def require(session: Session, capability: str) -> None:
    if not session.allows(capability) and not can(session.role, capability):
        raise PermissionError(capability, session.role)


def require_any(session: Session, *capabilities: str) -> None:
    if any(session.allows(item) or can(session.role, item) for item in capabilities):
        return
    raise PermissionError(",".join(capabilities), session.role)


def can_launch(session: Session) -> bool:
    return can(session.role, Capability.LAUNCH_JOBS.value) or session.allows(Capability.LAUNCH_JOBS.value)


def can_stop(session: Session) -> bool:
    return can(session.role, Capability.STOP_JOBS.value) or session.allows(Capability.STOP_JOBS.value)


def gaps(session: Session, *required: str) -> frozenset[str]:
    missing = missing_capabilities(session.role, required)
    return frozenset(item for item in missing if item not in session.capabilities)

"""Session kinds for the Security Console.

FastAPI adapters (JWT, API key) live in the dashboard. This module is the
only place that names session kinds and their capabilities so demo login,
guest, API keys, and JWTs stop being confused with each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class SessionKind(StrEnum):
    DEMO = "demo"
    GUEST = "guest"
    API_KEY = "api_key"
    JWT = "jwt"


ANALYST_CAPABILITIES: frozenset[str] = frozenset(
    {
        "viewFindings",
        "viewJobs",
        "viewTargets",
        "viewAuditLogs",
        "triageFindings",
    }
)

VIEWER_CAPABILITIES: frozenset[str] = frozenset(
    {
        "viewFindings",
        "viewJobs",
        "viewTargets",
    }
)

GUEST_CAPABILITIES: frozenset[str] = frozenset({"viewFindings"})

_ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "analyst": ANALYST_CAPABILITIES,
    "operator": ANALYST_CAPABILITIES,
    "admin": ANALYST_CAPABILITIES | frozenset({"manageKeys", "modifySettings"}),
    "viewer": VIEWER_CAPABILITIES,
    "guest": GUEST_CAPABILITIES,
}


def capabilities_for_role(role: str) -> frozenset[str]:
    normalized = str(role or "viewer").strip().lower()
    return _ROLE_CAPABILITIES.get(normalized, VIEWER_CAPABILITIES)


@dataclass(frozen=True, slots=True)
class Session:
    kind: SessionKind
    subject: str
    role: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    bearer_token: str | None = None

    @property
    def has_bearer_token(self) -> bool:
        return bool(self.bearer_token)

    def allows(self, capability: str) -> bool:
        return capability in self.capabilities


def demo_session(name: str = "Demo Analyst", role: str = "analyst") -> Session:
    subject = str(name or "").strip() or "Demo Analyst"
    normalized_role = str(role or "analyst").strip().lower() or "analyst"
    return Session(
        kind=SessionKind.DEMO,
        subject=subject,
        role=normalized_role,
        capabilities=capabilities_for_role(normalized_role),
        bearer_token=None,
    )


def guest_session(subject: str = "guest") -> Session:
    return Session(
        kind=SessionKind.GUEST,
        subject=subject,
        role="guest",
        capabilities=capabilities_for_role("guest"),
        bearer_token=None,
    )


def jwt_session(subject: str, role: str, token: str) -> Session:
    return Session(
        kind=SessionKind.JWT,
        subject=subject,
        role=role,
        capabilities=capabilities_for_role(role),
        bearer_token=token,
    )


def api_key_session(subject: str, role: str, token: str) -> Session:
    return Session(
        kind=SessionKind.API_KEY,
        subject=subject,
        role=role,
        capabilities=capabilities_for_role(role),
        bearer_token=token,
    )

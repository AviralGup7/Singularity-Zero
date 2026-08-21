"""Auth domain: session kinds and capabilities. No FastAPI imports."""

from src.auth.policy import is_demo_or_guest, requires_bearer_token
from src.auth.session import (
    ANALYST_CAPABILITIES,
    Session,
    SessionKind,
    api_key_session,
    capabilities_for_role,
    demo_session,
    guest_session,
    jwt_session,
)

__all__ = [
    "ANALYST_CAPABILITIES",
    "Session",
    "SessionKind",
    "api_key_session",
    "capabilities_for_role",
    "demo_session",
    "guest_session",
    "is_demo_or_guest",
    "jwt_session",
    "requires_bearer_token",
]

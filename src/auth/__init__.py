"""Auth domain: session kinds and capabilities. No FastAPI imports."""

from src.auth.audit import AuthAuditAction, AuthAuditLog
from src.auth.capabilities import Capability, can, matrix_capabilities
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
from src.auth.sessions import SessionRegistry, describe

__all__ = [
    "ANALYST_CAPABILITIES",
    "AuthAuditAction",
    "AuthAuditLog",
    "Capability",
    "Session",
    "SessionKind",
    "SessionRegistry",
    "api_key_session",
    "can",
    "capabilities_for_role",
    "demo_session",
    "describe",
    "guest_session",
    "is_demo_or_guest",
    "jwt_session",
    "matrix_capabilities",
    "requires_bearer_token",
]

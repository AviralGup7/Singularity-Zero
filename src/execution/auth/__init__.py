"""Authentication subsystem.

Public entry point that aggregates :class:`AuthFlowRunner` and
:class:`OAuthAuthenticator` so callers can ``from src.execution.auth
import AuthFlowRunner``.
"""

from src.execution.auth.auth_flow import (
    AuthFlowRunner,
    AuthSpec,
    AuthStep,
    OAuthAuthenticator,
    SessionContext,
)
from src.execution.auth.select import normalize_auth_flow_engine, resolve_auth_flow_runner_cls

__all__ = [
    "AuthFlowRunner",
    "AuthSpec",
    "AuthStep",
    "OAuthAuthenticator",
    "SessionContext",
    "normalize_auth_flow_engine",
    "resolve_auth_flow_runner_cls",
]

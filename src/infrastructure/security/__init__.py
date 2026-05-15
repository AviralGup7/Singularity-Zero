"""Security package for the Cyber Security Test Pipeline.

Provides authentication, authorization, rate limiting, input validation,
CORS configuration, security headers, encryption, and audit logging
for the dashboard API and internal services.

Packages:
    auth: JWT authentication, API key management, RBAC, session management
    rate_limiter: Sliding window rate limiting with Redis support
    input_validation: URL, target name, and payload validation
    cors: Configurable CORS middleware
    headers: Security HTTP headers middleware
    encryption: Data encryption utilities and secret management
    audit: Tamper-evident audit logging
    config: Centralized security configuration

Usage:
    from src.infrastructure.security import SecurityConfig, AuthManager, AuditLogger
    from src.infrastructure.security.middleware import SecurityMiddleware

Example:
    config = SecurityConfig()
    auth = AuthManager(config)
    audit = AuditLogger(config)
"""

from src.infrastructure.security.audit import AuditEvent, AuditLogger, AuditSeverity
from src.infrastructure.security.auth import APIKey, AuthManager, Role, TokenPayload
from src.infrastructure.security.config import SecurityConfig

__version__ = "1.0.0"

__all__ = [
    "SecurityConfig",
    "AuthManager",
    "Role",
    "TokenPayload",
    "APIKey",
    "AuditLogger",
    "AuditEvent",
    "AuditSeverity",
    "__version__",
]

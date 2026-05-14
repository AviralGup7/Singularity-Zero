"""Authentication system for the Cyber Security Test Pipeline.

Provides JWT token generation and validation, API key management,
role-based access control (RBAC), token refresh, session management,
and password hashing for dashboard admin users.
"""

from .api_keys import APIKeyStore, generate_api_key, hash_api_key
from .jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_jwt,
    encode_jwt,
    validate_token,
)
from .manager import AuthManager
from .models import APIKey, PasswordHash, Role, Session, TokenPayload
from .passwords import (
    hash_password,
    validate_password_strength,
    verify_password,
)

__all__ = [
    "Role",
    "TokenPayload",
    "APIKey",
    "Session",
    "PasswordHash",
    "AuthManager",
    "create_access_token",
    "create_refresh_token",
    "validate_token",
    "encode_jwt",
    "decode_jwt",
    "APIKeyStore",
    "generate_api_key",
    "hash_api_key",
    "hash_password",
    "verify_password",
    "validate_password_strength",
]

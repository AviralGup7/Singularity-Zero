"""Authentication system for the Cyber Security Test Pipeline.

This module re-exports all public symbols from the auth package
for backward compatibility with existing imports.

See auth/ package for the modular implementation:
    auth/models.py     - Role, TokenPayload, APIKey, Session, PasswordHash
    auth/jwt_handler.py - JWT encoding/decoding, token creation/validation
    auth/api_keys.py    - API key store and lifecycle management
    auth/passwords.py   - Password hashing and validation
    auth/manager.py     - AuthManager composition orchestrator
"""

from src.infrastructure.security.auth.api_keys import APIKeyStore, generate_api_key, hash_api_key
from src.infrastructure.security.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_jwt,
    encode_jwt,
    validate_token,
)
from src.infrastructure.security.auth.manager import AuthManager
from src.infrastructure.security.auth.models import (
    APIKey,
    PasswordHash,
    Role,
    Session,
    TokenPayload,
)
from src.infrastructure.security.auth.passwords import (
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

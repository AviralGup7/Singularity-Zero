"""Models for the authentication system.

Contains Role enum, TokenPayload, APIKey, Session, and PasswordHash models
used throughout the authentication pipeline.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Role(StrEnum):
    """User roles for role-based access control.

    Roles define permission levels:
        ADMIN: Full access to all resources and administrative functions.
            Can manage users, API keys, system configuration, and all jobs.
        OPERATOR: Can create, manage, and monitor scan jobs.
            Cannot modify system configuration or manage users.
        VIEWER: Read-only access to jobs, findings, and reports.
            Cannot create or modify any resources.
    """

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

    @property
    def permissions(self) -> set[str]:
        """Return the set of permissions for this role.

        Returns:
            Set of permission strings.
        """
        permission_map: dict[Role, set[str]] = {
            Role.ADMIN: {
                "jobs:create",
                "jobs:read",
                "jobs:update",
                "jobs:delete",
                "jobs:cancel",
                "targets:read",
                "targets:create",
                "targets:delete",
                "findings:read",
                "notes:create",
                "notes:update",
                "notes:delete",
                "cache:read",
                "cache:clear",
                "config:read",
                "config:update",
                "users:read",
                "users:create",
                "users:delete",
                "apikeys:read",
                "apikeys:create",
                "apikeys:revoke",
                "audit:read",
                "audit:export",
                "system:restart",
            },
            Role.OPERATOR: {
                "jobs:create",
                "jobs:read",
                "jobs:update",
                "jobs:cancel",
                "targets:read",
                "targets:create",
                "findings:read",
                "notes:create",
                "notes:update",
                "cache:read",
                "apikeys:read",
                "apikeys:create",
            },
            Role.VIEWER: {
                "jobs:read",
                "targets:read",
                "findings:read",
                "notes:read",
                "cache:read",
            },
        }
        return permission_map.get(self, set())

    def has_permission(self, permission: str) -> bool:
        """Check if this role has a specific permission.

        Args:
            permission: Permission string (e.g., "jobs:create").

        Returns:
            True if the role has the permission.
        """
        return permission in self.permissions


class TokenPayload(BaseModel):
    """Pydantic model for JWT token claims.

    Attributes:
        sub: Subject (user ID).
        role: User role.
        iat: Issued at timestamp.
        exp: Expiration timestamp.
        iss: Token issuer.
        aud: Token audience.
        jti: JWT ID (unique token identifier).
        sid: Session ID (optional, for session tracking).
    """

    sub: str = Field(..., min_length=1, description="User ID (subject)")
    role: str = Field(default=Role.VIEWER.value, description="User role as string")
    iat: float = Field(default_factory=lambda: datetime.now(UTC).timestamp())
    exp: float = Field(..., description="Expiration timestamp")
    iss: str = Field(default="cyber-security-pipeline")
    aud: str = Field(default="pipeline-dashboard")
    jti: str = Field(default_factory=lambda: uuid.uuid4().hex)
    sid: str | None = Field(default=None, description="Session ID")
    type: str = Field(default="access", description="Token type: access or refresh")

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.now(UTC).timestamp() > self.exp

    @property
    def expires_in_seconds(self) -> float:
        """Return seconds until token expiration."""
        return max(0, self.exp - datetime.now(UTC).timestamp())


class APIKey(BaseModel):
    """Pydantic model for API key storage and validation.

    Attributes:
        id: Unique key identifier.
        user_id: Owner user ID.
        name: Human-readable key name.
        key_hash: SHA-256 hash of the raw key (never store raw keys).
        key_prefix: First 8 characters of raw key for identification.
        role: Role associated with this key.
        created_at: Creation timestamp.
        expires_at: Expiration timestamp (None for no expiry).
        last_used_at: Last usage timestamp.
        is_active: Whether the key is active.
        is_revoked: Whether the key has been revoked.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=128)
    key_hash: str = Field(..., min_length=64)
    key_prefix: str = Field(..., min_length=1, max_length=16)
    role: Role = Field(default=Role.VIEWER)
    created_at: float = Field(default_factory=lambda: datetime.now(UTC).timestamp())
    expires_at: float | None = Field(default=None)
    last_used_at: float | None = Field(default=None)
    is_active: bool = Field(default=True)
    is_revoked: bool = Field(default=False)

    @property
    def is_expired(self) -> bool:
        """Check if the key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC).timestamp() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if the key is valid (active, not revoked, not expired)."""
        return self.is_active and not self.is_revoked and not self.is_expired


class Session(BaseModel):
    """Pydantic model for session tracking.

    Attributes:
        id: Unique session identifier.
        user_id: Associated user ID.
        role: User role at session creation.
        created_at: Session creation timestamp.
        last_active: Last activity timestamp.
        expires_at: Session expiration timestamp.
        ip_address: Client IP address.
        user_agent: Client user agent string.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str = Field(..., min_length=1)
    role: Role = Field(default=Role.VIEWER)
    created_at: float = Field(default_factory=lambda: datetime.now(UTC).timestamp())
    last_active: float = Field(default_factory=lambda: datetime.now(UTC).timestamp())
    expires_at: float = Field(...)
    ip_address: str = Field(default="")
    user_agent: str = Field(default="")

    @property
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.now(UTC).timestamp() > self.expires_at

    @property
    def is_active(self) -> bool:
        """Check if the session is still active."""
        return not self.is_expired


class PasswordHash(BaseModel):
    """Pydantic model for password hashing utilities.

    Uses PBKDF2-HMAC-SHA256 with a random salt for secure password storage.

    Attributes:
        algorithm: Hashing algorithm identifier.
        iterations: Number of PBKDF2 iterations.
        salt: Random salt (hex-encoded).
        hash: Password hash (hex-encoded).
    """

    algorithm: str = Field(default="pbkdf2_sha256")
    iterations: int = Field(default=600000, ge=100000)
    salt: str = Field(..., min_length=32)
    hash: str = Field(..., min_length=64)

    @classmethod
    def create(cls, password: str, iterations: int = 600000) -> PasswordHash:
        """Create a new password hash from a plaintext password.

        Args:
            password: Plaintext password to hash.
            iterations: Number of PBKDF2 iterations (higher = more secure).

        Returns:
            PasswordHash instance with salt and hash.
        """
        salt = secrets.token_hex(32)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return cls(
            algorithm="pbkdf2_sha256",
            iterations=iterations,
            salt=salt,
            hash=pwd_hash.hex(),
        )

    def verify(self, password: str) -> bool:
        """Verify a plaintext password against this hash.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            password: Plaintext password to verify.

        Returns:
            True if the password matches.
        """
        import hmac

        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.salt.encode("utf-8"),
            self.iterations,
        )
        return hmac.compare_digest(pwd_hash.hex(), self.hash)

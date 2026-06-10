"""Authentication manager that composes JWT, API keys, sessions, and passwords."""

import ipaddress
import re
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from src.infrastructure.security.config import SecurityConfig

from .api_keys import APIKeyStore
from .jwt_handler import (
    create_access_token as _create_access_token,
)
from .jwt_handler import (
    create_refresh_token as _create_refresh_token,
)
from .jwt_handler import (
    validate_token as _validate_token,
)
from .models import APIKey, PasswordHash, Role, Session, TokenPayload
from .passwords import hash_password as _hash_password
from .passwords import verify_password as _verify_password


class _AuditSink(Protocol):
    def log(self, *args: Any, **kwargs: Any) -> Any: ...


class AuthManager:
    """Main authentication orchestrator.

    Manages JWT token generation/validation, API key lifecycle,
    session management, and password hashing.

    SECURITY NOTE: The following stores are in-memory and do NOT
    survive process restarts:
    - _sessions: Active sessions are lost on restart.
    - _revoked_tokens: Token revocations are lost on restart.
    - _passwords: Password hashes are lost on restart.

    For production deployments, these MUST be backed by a durable
    store (Redis, SQLite, or a database) with the same atomicity
    guarantees as the AuditLogger's SQLite index.

    Attributes:
        config: Security configuration.
        _api_key_store: API key store and lifecycle manager.
        _sessions: In-memory session store (session_id -> Session).
        _passwords: In-memory password store (user_id -> PasswordHash).
        _revoked_tokens: Set of revoked JWT IDs.
    """

    def __init__(self, config: SecurityConfig, audit_logger: _AuditSink | None = None) -> None:
        """Initialize the authentication manager.

        Args:
            config: Security configuration.
        """
        self.config = config
        self._api_key_store = APIKeyStore(config, audit_logger=audit_logger)
        self._sessions: dict[str, Session] = {}
        self._passwords: dict[str, PasswordHash] = {}
        self._revoked_tokens: set[str] = set()
        self._revoked_tokens_lock = threading.Lock()
        self._session_lock = threading.Lock()

    # JWT Token Management

    def create_access_token(
        self,
        user_id: str,
        role: Role = Role.VIEWER,
        session_id: str | None = None,
    ) -> str:
        """Create a JWT access token.

        Args:
            user_id: User identifier.
            role: User role for authorization.
            session_id: Optional session ID for tracking (stored in JWT sid claim).

        Returns:
            Encoded JWT access token string.
        """
        return _create_access_token(
            subject=user_id,
            role=role,
            config=self.config,
        )

    def create_refresh_token(
        self,
        user_id: str,
        role: Role = Role.VIEWER,
        session_id: str | None = None,
    ) -> str:
        """Create a JWT refresh token.

        Args:
            user_id: User identifier.
            role: User role for authorization.
            session_id: Optional session ID for tracking.

        Returns:
            Encoded JWT refresh token string.
        """
        return _create_refresh_token(
            subject=user_id,
            role=role,
            config=self.config,
        )

    def validate_token(self, token: str) -> TokenPayload | None:
        """Validate a JWT token and return its payload.

        Args:
            token: JWT token string.

        Returns:
            TokenPayload if valid, None otherwise.
        """
        payload = _validate_token(token, self.config)
        # Additional revocation check
        if payload is not None:
            with self._revoked_tokens_lock:
                if payload.jti in self._revoked_tokens:
                    return None
        return payload

    def refresh_access_token(self, refresh_token: str) -> tuple[str, str] | None:
        """Use a refresh token to generate a new access token.

        Args:
            refresh_token: Valid JWT refresh token.

        Returns:
            Tuple of (new_access_token, refresh_token) or None if invalid.
        """
        payload = self.validate_token(refresh_token)
        if payload is None:
            return None

        new_access = self.create_access_token(
            user_id=payload.sub,
            role=Role(payload.role) if payload.role else Role.VIEWER,
            session_id=payload.sid,
        )

        return new_access, refresh_token

    def revoke_token(self, token_id: str) -> None:
        """Revoke a JWT token by its JTI.

        Args:
            token_id: JWT ID (jti) to revoke.
        """
        with self._revoked_tokens_lock:
            self._revoked_tokens.add(token_id)

    # API Key Management

    def create_api_key(
        self,
        user_id: str,
        name: str,
        role: Role = Role.VIEWER,
        expires_days: int | None = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key for a user.

        Args:
            user_id: Owner user ID.
            name: Human-readable key name.
            role: Role associated with this key.
            expires_days: Days until key expires (None for no expiry).

        Returns:
            Tuple of (raw_key, APIKey model). The raw key is only
            returned once and must be stored securely by the caller.

        Raises:
            ValueError: If user has reached maximum key limit.
        """
        return self._api_key_store.create(user_id, name, role, expires_days)

    def validate_api_key(self, raw_key: str) -> APIKey | None:
        """Validate an API key and return its model if valid.

        Args:
            raw_key: Raw API key string.

        Returns:
            APIKey if valid, None otherwise.
        """
        return self._api_key_store.validate(raw_key)

    def rotate_api_key(self, key_id: str) -> tuple[str, APIKey] | None:
        """Rotate an API key by revoking the old one and creating a new one.

        Args:
            key_id: ID of the key to rotate.

        Returns:
            Tuple of (new_raw_key, new_APIKey) or None if key not found.
        """
        return self._api_key_store.rotate(key_id)

    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key.

        Args:
            key_id: ID of the key to revoke.

        Returns:
            True if the key was found and revoked.
        """
        return self._api_key_store.revoke(key_id)

    def list_user_api_keys(self, user_id: str) -> list[APIKey]:
        """List all API keys for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of APIKey models.
        """
        return self._api_key_store.list_keys(user_id)

    def export_api_keys_sealed_bundle(self, passphrase: str, *, name: str = "api-key-store") -> str:
        """Export API key metadata as a sealed bundle for offline runners."""
        return self._api_key_store.export_sealed_bundle(passphrase, name=name)

    def import_api_keys_sealed_bundle(self, bundle: str | bytes, passphrase: str) -> None:
        """Import API key metadata from a sealed bundle."""
        self._api_key_store.import_sealed_bundle(bundle, passphrase)

    # Session Management

    def create_session(
        self,
        user_id: str,
        role: Role,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Session:
        """Create a new session for a user.

        Args:
            user_id: User identifier.
            role: User role.
            ip_address: Client IP address (validated and sanitized).
            user_agent: Client user agent string (truncated and sanitized).

        Returns:
            New Session instance.
        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self.config.session.timeout_minutes)

        # SECURITY: Validate and sanitize IP address to prevent injection
        # into logs or JSON serialization.
        sanitized_ip = self._sanitize_ip(ip_address)
        # SECURITY: Truncate and sanitize user agent to prevent log injection
        # and excessive memory usage from malicious headers.
        sanitized_ua = self._sanitize_user_agent(user_agent)

        session = Session(
            user_id=user_id,
            role=role,
            expires_at=expires_at.timestamp(),
            ip_address=sanitized_ip,
            user_agent=sanitized_ua,
        )

        self._sessions[session.id] = session
        return session

    @staticmethod
    def _sanitize_ip(ip: str) -> str:
        """Validate and sanitize an IP address string.

        Returns the validated IP or empty string if invalid.
        """
        if not ip:
            return ""
        try:
            addr = ipaddress.ip_address(ip)
            return str(addr)
        except ValueError:
            return ""

    @staticmethod
    def _sanitize_user_agent(ua: str, max_length: int = 512) -> str:
        """Sanitize a User-Agent string.

        Truncates to max_length and removes control characters.
        """
        if not ua:
            return ""
        # Remove control characters except common whitespace
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", ua)
        return sanitized[:max_length]

    def get_session(self, session_id: str) -> Session | None:
        """Get a session by ID.

        Args:
            session_id: Session identifier.

        Returns:
            Session if found and active, None otherwise.
        """
        with self._session_lock:
            session = self._sessions.get(session_id)
            if session is None or not session.is_active:
                return None
            session.last_active = datetime.now(UTC).timestamp()
            return session

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session.

        Args:
            session_id: Session identifier.

        Returns:
            True if the session was found and invalidated.
        """
        with self._session_lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.expires_at = datetime.now(UTC).timestamp() - 1
            return True

    def get_user_sessions(self, user_id: str) -> list[Session]:
        """Get all active sessions for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of active Session instances.
        """
        return [s for s in self._sessions.values() if s.user_id == user_id and s.is_active]

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions.

        Returns:
            Number of sessions removed.
        """
        expired_ids = [sid for sid, session in self._sessions.items() if session.is_expired]
        for sid in expired_ids:
            del self._sessions[sid]
        return len(expired_ids)

    # Password Management

    def set_password(self, user_id: str, password: str) -> PasswordHash:
        """Set or update a user's password.

        Args:
            user_id: User identifier.
            password: Plaintext password.

        Returns:
            PasswordHash instance.
        """
        pwd_hash = _hash_password(password)
        self._passwords[user_id] = pwd_hash
        return pwd_hash

    def verify_password(self, user_id: str, password: str) -> bool:
        """Verify a user's password.

        Uses constant-time dummy hash comparison when the user does not
        exist to prevent user enumeration via timing side-channel.

        Args:
            user_id: User identifier.
            password: Plaintext password to verify.

        Returns:
            True if the password is correct.
        """
        pwd_hash = self._passwords.get(user_id)
        if pwd_hash is None:
            # Perform a dummy hash to prevent timing-based user enumeration.
            # The time taken should be indistinguishable from a real hash check.
            from .passwords import hash_password as _dummy_hash
            _dummy_hash(password)
            return False
        return _verify_password(password, pwd_hash)

    def has_user(self, user_id: str) -> bool:
        """Check if a user exists (has a password set).

        SECURITY NOTE: This method is intentionally NOT timing-safe.
        Use verify_password() for authentication flows. This method
        should only be used for administrative operations where the
        caller already has authorization context.

        Args:
            user_id: User identifier.

        Returns:
            True if the user exists.
        """
        return user_id in self._passwords

    # Authorization

    def check_permission(self, token: TokenPayload, permission: str) -> bool:
        """Check if a token has a specific permission.

        Args:
            token: Validated token payload.
            permission: Permission string to check.

        Returns:
            True if the token's role has the permission.
        """
        try:
            role = Role(token.role)
            return role.has_permission(permission)
        except ValueError:
            return False

    def require_role(self, token: TokenPayload, *roles: Role) -> bool:
        """Check if a token has one of the required roles.

        Args:
            token: Validated token payload.
            *roles: Acceptable roles.

        Returns:
            True if the token's role is in the acceptable roles.
        """
        try:
            role = Role(token.role)
            return role in roles
        except ValueError:
            return False

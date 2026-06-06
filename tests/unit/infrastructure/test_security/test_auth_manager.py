import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import pytest
from src.infrastructure.security.audit import AuditEntry, AuditEvent, AuditLogger, AuditSeverity
from src.infrastructure.security.auth import (
    APIKey,
    AuthManager,
    PasswordHash,
    Role,
    Session,
    TokenPayload,
)
from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.encryption import (
    DataEncryptor,
    SecretManager,
    TLSConfig,
    generate_fernet_key,
)
from src.infrastructure.security.input_validation import (
    FileUploadValidator,
    InputValidator,
    JobPayloadValidator,
    TargetNameValidator,
    URLValidator,
    ValidationResult,
    ValidationRule,
)
from src.infrastructure.security.rate_limiter import (
    RateLimiter,
    RateLimitResult,
    SlidingWindowCounter,
)

class SecurityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.security_config = make_security_config()

class TestAuthManager(SecurityTestBase):
    def test_create_access_token(self) -> None:
        auth = AuthManager(self.security_config)
        token = auth.create_access_token(user_id="user1", role=Role.ADMIN)
        assert token is not None
        assert isinstance(token, str)

    def test_validate_token(self) -> None:
        auth = AuthManager(self.security_config)
        token = auth.create_access_token(user_id="user1", role=Role.ADMIN)
        payload = auth.validate_token(token)
        assert payload is not None
        assert payload.sub == "user1"
        assert payload.role == Role.ADMIN

    def test_validate_invalid_token(self) -> None:
        auth = AuthManager(self.security_config)
        payload = auth.validate_token("invalid.token.here")
        assert payload is None

    def test_revoke_token(self) -> None:
        auth = AuthManager(self.security_config)
        token = auth.create_access_token(user_id="user1")
        payload = auth.validate_token(token)
        assert payload is not None
        auth.revoke_token(payload.jti)
        assert auth.validate_token(token) is None

    def test_create_api_key(self) -> None:
        auth = AuthManager(self.security_config)
        raw_key, api_key = auth.create_api_key(user_id="user1", name="test-key")
        assert raw_key.startswith("csp_")
        assert api_key.user_id == "user1"
        assert api_key.name == "test-key"

    def test_validate_api_key(self) -> None:
        auth = AuthManager(self.security_config)
        raw_key, api_key = auth.create_api_key(user_id="user1", name="test-key")
        validated = auth.validate_api_key(raw_key)
        assert validated is not None
        assert validated.user_id == "user1"

    def test_revoke_api_key(self) -> None:
        auth = AuthManager(self.security_config)
        _, api_key = auth.create_api_key(user_id="user1", name="test-key")
        assert auth.revoke_api_key(api_key.id) is True
        assert auth.revoke_api_key("nonexistent") is False

    def test_list_user_api_keys(self) -> None:
        auth = AuthManager(self.security_config)
        auth.create_api_key(user_id="user1", name="key1")
        auth.create_api_key(user_id="user1", name="key2")
        keys = auth.list_user_api_keys("user1")
        assert len(keys) == 2

    def test_create_session(self) -> None:
        auth = AuthManager(self.security_config)
        session = auth.create_session(user_id="user1", role=Role.ADMIN)
        assert session.user_id == "user1"
        assert session.role == Role.ADMIN

    def test_get_session(self) -> None:
        auth = AuthManager(self.security_config)
        session = auth.create_session(user_id="user1", role=Role.VIEWER)
        retrieved = auth.get_session(session.id)
        assert retrieved is not None
        assert retrieved.user_id == "user1"

    def test_invalidate_session(self) -> None:
        auth = AuthManager(self.security_config)
        session = auth.create_session(user_id="user1", role=Role.VIEWER)
        assert auth.invalidate_session(session.id) is True
        assert auth.get_session(session.id) is None

    def test_set_and_verify_password(self) -> None:
        auth = AuthManager(self.security_config)
        auth.set_password("user1", "mypassword")
        assert auth.verify_password("user1", "mypassword") is True
        assert auth.verify_password("user1", "wrong") is False

    def test_has_user(self) -> None:
        auth = AuthManager(self.security_config)
        auth.set_password("user1", "password")
        assert auth.has_user("user1") is True
        assert auth.has_user("unknown") is False

    def test_check_permission(self) -> None:
        auth = AuthManager(self.security_config)
        token = TokenPayload(sub="user1", role=Role.ADMIN, exp=time.time() + 3600)
        assert auth.check_permission(token, "jobs:create") is True
        assert auth.check_permission(token, "users:delete") is True

    def test_require_role(self) -> None:
        auth = AuthManager(self.security_config)
        token = TokenPayload(sub="user1", role=Role.ADMIN, exp=time.time() + 3600)
        assert auth.require_role(token, Role.ADMIN) is True
        assert auth.require_role(token, Role.VIEWER) is False
        assert auth.require_role(token, Role.ADMIN, Role.OPERATOR) is True

    def test_cleanup_expired_sessions(self) -> None:
        auth = AuthManager(self.security_config)
        auth.create_session(user_id="user1", role=Role.VIEWER)
        auth._sessions["expired"] = Session(
            user_id="user2", role=Role.VIEWER, expires_at=time.time() - 10
        )
        removed = auth.cleanup_expired_sessions()
        assert removed >= 1

    def test_max_api_keys(self) -> None:
        self.security_config.api_key.max_keys_per_user = 2
        auth = AuthManager(self.security_config)
        auth.create_api_key(user_id="user1", name="key1")
        auth.create_api_key(user_id="user1", name="key2")
        with pytest.raises(ValueError):
            auth.create_api_key(user_id="user1", name="key3")
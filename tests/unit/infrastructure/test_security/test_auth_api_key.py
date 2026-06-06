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



class TestAPIKey(unittest.TestCase):
    def test_api_key_defaults(self) -> None:
        key = APIKey(user_id="u1", name="test", key_hash="a" * 64, key_prefix="csp_abc")
        assert key.is_active is True
        assert key.is_revoked is False
        assert key.role == Role.VIEWER

    def test_api_key_not_expired(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() + 3600,
        )
        assert key.is_expired is False

    def test_api_key_expired(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() - 10,
        )
        assert key.is_expired is True

    def test_api_key_valid(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() + 3600,
        )
        assert key.is_valid is True

    def test_api_key_invalid_revoked(self) -> None:
        key = APIKey(
            user_id="u1", name="test", key_hash="a" * 64, key_prefix="csp_abc", is_revoked=True
        )
        assert key.is_valid is False
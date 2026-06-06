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



class TestTokenPayload(unittest.TestCase):
    def test_token_defaults(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() + 3600)
        assert payload.sub == "user1"
        assert payload.role == Role.VIEWER
        assert payload.iss == "cyber-security-pipeline"
        assert payload.aud == "pipeline-dashboard"

    def test_token_not_expired(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() + 3600)
        assert payload.is_expired is False

    def test_token_expired(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() - 10)
        assert payload.is_expired is True

    def test_expires_in_seconds(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() + 100)
        assert payload.expires_in_seconds > 90
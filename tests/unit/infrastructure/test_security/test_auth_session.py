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



class TestSession(unittest.TestCase):
    def test_session_not_expired(self) -> None:
        session = Session(user_id="u1", expires_at=time.time() + 3600)
        assert session.is_expired is False
        assert session.is_active is True

    def test_session_expired(self) -> None:
        session = Session(user_id="u1", expires_at=time.time() - 10)
        assert session.is_expired is True
        assert session.is_active is False
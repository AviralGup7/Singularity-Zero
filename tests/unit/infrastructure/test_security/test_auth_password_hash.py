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



class TestPasswordHash(unittest.TestCase):
    def test_create_and_verify(self) -> None:
        ph = PasswordHash.create("secure_password")
        assert ph.algorithm == "pbkdf2_sha256"
        assert ph.verify("secure_password") is True
        assert ph.verify("wrong_password") is False

    def test_different_passwords(self) -> None:
        ph1 = PasswordHash.create("password1")
        ph2 = PasswordHash.create("password1")
        assert ph1.salt != ph2.salt
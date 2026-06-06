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

class TestJobPayloadValidator(SecurityTestBase):
    def test_valid_payload(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            target_name="test-target",
            mode="idor",
        )
        assert result.is_valid is True

    def test_invalid_mode(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            mode="invalid_mode",
        )
        assert result.is_valid is False

    def test_invalid_modules(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            modules=["valid", "invalid module!"],
        )
        assert result.is_valid is False
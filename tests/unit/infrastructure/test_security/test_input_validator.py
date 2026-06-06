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

class TestInputValidator(SecurityTestBase):
    def test_sanitize_string(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.sanitize_string("hello\x00world")
        assert "\x00" not in result

    def test_sanitize_dict(self) -> None:
        validator = InputValidator(self.security_config)
        data = {"key": "value\x00", "nested": {"a": "b"}}
        result = validator.sanitize_dict(data)
        assert "\x00" not in result["key"]

    def test_check_request_size(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.check_request_size(100)
        assert result.is_valid is True

    def test_check_request_size_too_large(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.check_request_size(100 * 1024 * 1024)
        assert result.is_valid is False
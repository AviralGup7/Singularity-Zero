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

class TestFileUploadValidator(SecurityTestBase):
    def test_valid_filename(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("report.json")
        assert result.is_valid is True

    def test_dangerous_extension(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("malware.exe")
        assert result.is_valid is False

    def test_path_separator(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("../../etc/passwd")
        assert result.is_valid is False

    def test_null_byte(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_filename("file\x00.txt")
        assert result.is_valid is False

    def test_validate_size(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_size(100)
        assert result.is_valid is True

    def test_validate_size_too_large(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_size(10 * 1024 * 1024)
        assert result.is_valid is False

    def test_validate_content_type(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_content_type("application/json")
        assert result.is_valid is True

    def test_validate_content_type_invalid(self) -> None:
        validator = FileUploadValidator(self.security_config)
        result = validator.validate_content_type("application/octet-stream")
        assert result.is_valid is False
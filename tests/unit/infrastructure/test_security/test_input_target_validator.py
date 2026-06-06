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

import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase, make_security_config

class TestTargetNameValidator(SecurityTestBase):
    def test_valid_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("my-target-01")
        assert result.is_valid is True

    def test_empty_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("")
        assert result.is_valid is False

    def test_path_traversal(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("../etc/passwd")
        assert result.is_valid is False

    def test_starts_with_dot(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate(".hidden")
        assert result.is_valid is False

    def test_reserved_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        result = validator.validate("con")
        assert result.is_valid is False

    def test_sanitize_name(self) -> None:
        validator = TargetNameValidator(self.security_config)
        sanitized = validator._sanitize_name("my   target___name")
        assert sanitized == "my-target-name"
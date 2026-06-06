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



class TestRateLimitResult(unittest.TestCase):
    def test_defaults(self) -> None:
        result = RateLimitResult()
        assert result.allowed is True
        assert result.is_limited is False

    def test_limited(self) -> None:
        result = RateLimitResult(allowed=False, limit=10, remaining=0, retry_after=30)
        assert result.is_limited is True
        assert result.retry_after == 30

    def test_headers(self) -> None:
        result = RateLimitResult(limit=60, remaining=55, reset_at=1000.0)
        headers = result.headers
        assert headers["X-RateLimit-Limit"] == "60"
        assert headers["X-RateLimit-Remaining"] == "55"
        assert "Retry-After" not in headers

    def test_headers_when_limited(self) -> None:
        result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=1000.0, retry_after=30
        )
        headers = result.headers
        assert "Retry-After" in headers
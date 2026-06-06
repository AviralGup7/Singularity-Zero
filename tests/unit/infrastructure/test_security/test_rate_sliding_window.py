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



class TestSlidingWindowCounter(unittest.TestCase):
    def test_allows_under_limit(self) -> None:
        counter = SlidingWindowCounter(window_seconds=60)
        for _ in range(5):
            result = counter.increment("user1", limit=10)
            assert result.allowed is True

    def test_blocks_over_limit(self) -> None:
        counter = SlidingWindowCounter(window_seconds=60)
        for _ in range(10):
            counter.increment("user1", limit=10)
        result = counter.increment("user1", limit=10)
        assert result.allowed is False

    def test_different_keys(self) -> None:
        counter = SlidingWindowCounter(window_seconds=60)
        for _ in range(10):
            counter.increment("user1", limit=10)
        result = counter.increment("user2", limit=10)
        assert result.allowed is True

    def test_cleanup(self) -> None:
        counter = SlidingWindowCounter(window_seconds=60)
        counter.increment("old", limit=10)
        counter._counters["old"]["current_window_start"] = time.time() - 7200
        removed = counter.cleanup(max_age_seconds=3600)
        assert removed == 1
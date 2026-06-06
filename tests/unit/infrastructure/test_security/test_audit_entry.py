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



class TestAuditEntry(unittest.TestCase):
    def test_compute_hash(self) -> None:
        entry = AuditEntry(
            id=1, timestamp="2024-01-01T00:00:00", event="auth.success", severity="info"
        )
        h1 = entry.compute_hash()
        h2 = entry.compute_hash()
        assert h1 == h2

    def test_compute_hash_with_secret(self) -> None:
        entry = AuditEntry(
            id=1, timestamp="2024-01-01T00:00:00", event="auth.success", severity="info"
        )
        h1 = entry.compute_hash(hmac_secret="secret")
        h2 = entry.compute_hash(hmac_secret="different")
        assert h1 != h2

    def test_finalize(self) -> None:
        entry = AuditEntry(
            id=1, timestamp="2024-01-01T00:00:00", event="auth.success", severity="info"
        )
        entry.finalize()
        assert entry.entry_hash != ""
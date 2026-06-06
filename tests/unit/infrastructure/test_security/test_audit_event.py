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



class TestAuditEvent(unittest.TestCase):
    def test_event_values(self) -> None:
        assert AuditEvent.AUTH_SUCCESS.value == "auth.success"
        assert AuditEvent.AUTH_FAILURE.value == "auth.failure"
        assert AuditEvent.JOB_CREATE.value == "job.create"
        assert AuditEvent.SYSTEM_START.value == "system.start"

    def test_default_severity(self) -> None:
        assert AuditEvent.AUTH_SUCCESS.default_severity == AuditSeverity.INFO
        assert AuditEvent.AUTH_FAILURE.default_severity == AuditSeverity.WARNING
        assert AuditEvent.AUTHZ_FAILURE.default_severity == AuditSeverity.ERROR
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
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from _security_base import SecurityTestBase, make_security_config

class TestAuditLogger(SecurityTestBase):
    def setUp(self) -> None:
        super().setUp()
        log_path = self.security_config.audit.log_path
        if os.path.exists(log_path):
            os.remove(log_path)

    def test_log_entry(self) -> None:
        logger = AuditLogger(self.security_config)
        entry = logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="admin")
        assert entry.id == 1
        assert entry.event == "auth.success"
        logger.close()

    def test_log_multiple_entries(self) -> None:
        logger = AuditLogger(self.security_config)
        logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="admin")
        logger.log(event=AuditEvent.JOB_CREATE, user_id="admin")
        entries = logger.get_entries(limit=10)
        assert len(entries) == 2
        logger.close()

    def test_verify_integrity(self) -> None:
        logger = AuditLogger(self.security_config)
        logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="admin")
        valid, compromised = logger.verify_integrity()
        assert valid is True
        assert compromised == []
        logger.close()

    def test_export_logs(self) -> None:
        logger = AuditLogger(self.security_config)
        logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="admin")
        export_path = os.path.join(tempfile.gettempdir(), "exported_audit.log")
        count = logger.export_logs(export_path)
        assert count == 1
        if os.path.exists(export_path):
            os.remove(export_path)
        logger.close()

    def test_get_entries_with_filter(self) -> None:
        logger = AuditLogger(self.security_config)
        logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="admin")
        logger.log(event=AuditEvent.AUTH_FAILURE, user_id="unknown")
        entries = logger.get_entries(limit=10, event="auth.success")
        assert len(entries) == 1
        logger.close()

    def test_get_entries_with_user_filter(self) -> None:
        logger = AuditLogger(self.security_config)
        logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="admin")
        logger.log(event=AuditEvent.AUTH_SUCCESS, user_id="other")
        entries = logger.get_entries(limit=10, user_id="admin")
        assert len(entries) == 1
        logger.close()

    def test_get_entries_empty_log(self) -> None:
        self.security_config.audit.log_path = os.path.join(
            tempfile.gettempdir(), "nonexistent_audit.log"
        )
        logger = AuditLogger(self.security_config)
        entries = logger.get_entries()
        assert entries == []
        logger.close()
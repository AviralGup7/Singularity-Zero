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

class TestTLSConfig(SecurityTestBase):
    def test_defaults(self) -> None:
        config = TLSConfig()
        assert config.min_version == "1.2"
        assert config.ciphers == TLSConfig.RECOMMENDED_CIPHERS

    def test_from_security_config(self) -> None:
        config = TLSConfig(self.security_config)
        assert config is not None

    def test_get_uvicorn_ssl_kwargs(self) -> None:
        config = TLSConfig()
        kwargs = config.get_uvicorn_ssl_kwargs()
        assert "ssl_min_version" in kwargs
        assert "ssl_ciphers" in kwargs

    def test_get_gunicorn_ssl_kwargs(self) -> None:
        config = TLSConfig()
        kwargs = config.get_gunicorn_ssl_kwargs()
        assert "ssl_version" in kwargs
        assert "ciphers" in kwargs
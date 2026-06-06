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

class TestDataEncryptor(SecurityTestBase):
    def test_encrypt_decrypt_string(self) -> None:
        key = generate_fernet_key()
        encryptor = DataEncryptor(key)
        encrypted = encryptor.encrypt("secret data")
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == "secret data"

    def test_encrypt_decrypt_dict(self) -> None:
        key = generate_fernet_key()
        encryptor = DataEncryptor(key)
        data = {"key": "value", "number": 42}
        encrypted = encryptor.encrypt_dict(data)
        decrypted = encryptor.decrypt_dict(encrypted)
        assert decrypted == data

    def test_encrypt_bytes(self) -> None:
        key = generate_fernet_key()
        encryptor = DataEncryptor(key)
        encrypted = encryptor.encrypt(b"binary data")
        decrypted = encryptor.decrypt_bytes(encrypted)
        assert decrypted == b"binary data"

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError):
            DataEncryptor("")

    def test_invalid_key_raises(self) -> None:
        with pytest.raises(ValueError):
            DataEncryptor("not-a-valid-fernet-key")
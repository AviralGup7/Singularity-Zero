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



def make_security_config() -> SecurityConfig:
    with patch.object(SecurityConfig, "model_post_init", return_value=None):
        config = SecurityConfig.model_construct()
        config.jwt = MagicMock()
        config.jwt.secret = "test-secret-key-for-unit-tests-only"
        config.jwt.algorithm = "HS256"
        config.jwt.access_token_expiry_minutes = 30
        config.jwt.refresh_token_expiry_days = 7
        config.jwt.issuer = "cyber-security-pipeline"
        config.jwt.audience = "pipeline-dashboard"
        config.api_key = MagicMock()
        config.api_key.header_name = "X-API-Key"
        config.api_key.key_prefix = "csp_"
        config.api_key.rotation_days = 90
        config.api_key.max_keys_per_user = 5
        config.session = MagicMock()
        config.session.timeout_minutes = 60
        config.rate_limit = MagicMock()
        config.rate_limit.window_seconds = 60
        config.rate_limit.default_requests_per_minute = 60
        config.rate_limit.jobs_requests_per_minute = 10
        config.rate_limit.admin_requests_per_minute = 20
        config.rate_limit.replay_requests_per_minute = 30
        config.rate_limit.bypass_tokens = []
        config.rate_limit.redis_url = None
        config.cors = MagicMock()
        config.headers = MagicMock()
        config.encryption = MagicMock()
        config.audit = MagicMock()
        config.audit.log_path = os.path.join(tempfile.gettempdir(), "test_audit.log")
        config.audit.retention_days = 90
        config.audit.tamper_evident = True
        config.audit.hmac_secret = "test-hmac-secret"
        config.audit.max_log_size_mb = 100
        config.audit.rotate_on_size = True
        config.audit.export_format = "json"
        config.input_validation = MagicMock()
        config.input_validation.max_url_length = 2048
        config.input_validation.max_target_name_length = 255
        config.input_validation.max_payload_size_bytes = 1024 * 1024
        config.input_validation.max_request_body_bytes = 10 * 1024 * 1024
        config.input_validation.allowed_url_schemes = ["http", "https"]
        config.input_validation.blocked_target_patterns = [r"\.\.", r"/etc/"]
        config.input_validation.allowed_content_types = ["application/json"]
        return config


class SecurityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.security_config = make_security_config()
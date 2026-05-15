"""Unit tests for the security module."""

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


@pytest.fixture
def security_config() -> SecurityConfig:
    return make_security_config()


class SecurityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.security_config = make_security_config()


@pytest.mark.unit
class TestRole(unittest.TestCase):
    def test_role_values(self) -> None:
        assert Role.ADMIN.value == "admin"
        assert Role.OPERATOR.value == "operator"
        assert Role.VIEWER.value == "viewer"

    def test_admin_permissions(self) -> None:
        perms = Role.ADMIN.permissions
        assert "jobs:create" in perms
        assert "users:read" in perms
        assert "config:update" in perms

    def test_operator_permissions(self) -> None:
        perms = Role.OPERATOR.permissions
        assert "jobs:create" in perms
        assert "users:read" not in perms
        assert "config:update" not in perms

    def test_viewer_permissions(self) -> None:
        perms = Role.VIEWER.permissions
        assert "jobs:read" in perms
        assert "jobs:create" not in perms

    def test_has_permission(self) -> None:
        assert Role.ADMIN.has_permission("jobs:create") is True
        assert Role.VIEWER.has_permission("jobs:create") is False


@pytest.mark.unit
class TestTokenPayload(unittest.TestCase):
    def test_token_defaults(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() + 3600)
        assert payload.sub == "user1"
        assert payload.role == Role.VIEWER
        assert payload.iss == "cyber-security-pipeline"
        assert payload.aud == "pipeline-dashboard"

    def test_token_not_expired(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() + 3600)
        assert payload.is_expired is False

    def test_token_expired(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() - 10)
        assert payload.is_expired is True

    def test_expires_in_seconds(self) -> None:
        payload = TokenPayload(sub="user1", exp=time.time() + 100)
        assert payload.expires_in_seconds > 90


@pytest.mark.unit
class TestAPIKey(unittest.TestCase):
    def test_api_key_defaults(self) -> None:
        key = APIKey(user_id="u1", name="test", key_hash="a" * 64, key_prefix="csp_abc")
        assert key.is_active is True
        assert key.is_revoked is False
        assert key.role == Role.VIEWER

    def test_api_key_not_expired(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() + 3600,
        )
        assert key.is_expired is False

    def test_api_key_expired(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() - 10,
        )
        assert key.is_expired is True

    def test_api_key_valid(self) -> None:
        key = APIKey(
            user_id="u1",
            name="test",
            key_hash="a" * 64,
            key_prefix="csp_abc",
            expires_at=time.time() + 3600,
        )
        assert key.is_valid is True

    def test_api_key_invalid_revoked(self) -> None:
        key = APIKey(
            user_id="u1", name="test", key_hash="a" * 64, key_prefix="csp_abc", is_revoked=True
        )
        assert key.is_valid is False


@pytest.mark.unit
class TestSession(unittest.TestCase):
    def test_session_not_expired(self) -> None:
        session = Session(user_id="u1", expires_at=time.time() + 3600)
        assert session.is_expired is False
        assert session.is_active is True

    def test_session_expired(self) -> None:
        session = Session(user_id="u1", expires_at=time.time() - 10)
        assert session.is_expired is True
        assert session.is_active is False


@pytest.mark.unit
class TestPasswordHash(unittest.TestCase):
    def test_create_and_verify(self) -> None:
        ph = PasswordHash.create("secure_password")
        assert ph.algorithm == "pbkdf2_sha256"
        assert ph.verify("secure_password") is True
        assert ph.verify("wrong_password") is False

    def test_different_passwords(self) -> None:
        ph1 = PasswordHash.create("password1")
        ph2 = PasswordHash.create("password1")
        assert ph1.salt != ph2.salt


@pytest.mark.unit
class TestAuthManager(SecurityTestBase):
    def test_create_access_token(self) -> None:
        auth = AuthManager(self.security_config)
        token = auth.create_access_token(user_id="user1", role=Role.ADMIN)
        assert token is not None
        assert isinstance(token, str)

    def test_validate_token(self) -> None:
        auth = AuthManager(self.security_config)
        token = auth.create_access_token(user_id="user1", role=Role.ADMIN)
        payload = auth.validate_token(token)
        assert payload is not None
        assert payload.sub == "user1"
        assert payload.role == Role.ADMIN

    def test_validate_invalid_token(self) -> None:
        auth = AuthManager(self.security_config)
        payload = auth.validate_token("invalid.token.here")
        assert payload is None

    def test_revoke_token(self) -> None:
        auth = AuthManager(self.security_config)
        token = auth.create_access_token(user_id="user1")
        payload = auth.validate_token(token)
        assert payload is not None
        auth.revoke_token(payload.jti)
        assert auth.validate_token(token) is None

    def test_create_api_key(self) -> None:
        auth = AuthManager(self.security_config)
        raw_key, api_key = auth.create_api_key(user_id="user1", name="test-key")
        assert raw_key.startswith("csp_")
        assert api_key.user_id == "user1"
        assert api_key.name == "test-key"

    def test_validate_api_key(self) -> None:
        auth = AuthManager(self.security_config)
        raw_key, api_key = auth.create_api_key(user_id="user1", name="test-key")
        validated = auth.validate_api_key(raw_key)
        assert validated is not None
        assert validated.user_id == "user1"

    def test_revoke_api_key(self) -> None:
        auth = AuthManager(self.security_config)
        _, api_key = auth.create_api_key(user_id="user1", name="test-key")
        assert auth.revoke_api_key(api_key.id) is True
        assert auth.revoke_api_key("nonexistent") is False

    def test_list_user_api_keys(self) -> None:
        auth = AuthManager(self.security_config)
        auth.create_api_key(user_id="user1", name="key1")
        auth.create_api_key(user_id="user1", name="key2")
        keys = auth.list_user_api_keys("user1")
        assert len(keys) == 2

    def test_create_session(self) -> None:
        auth = AuthManager(self.security_config)
        session = auth.create_session(user_id="user1", role=Role.ADMIN)
        assert session.user_id == "user1"
        assert session.role == Role.ADMIN

    def test_get_session(self) -> None:
        auth = AuthManager(self.security_config)
        session = auth.create_session(user_id="user1", role=Role.VIEWER)
        retrieved = auth.get_session(session.id)
        assert retrieved is not None
        assert retrieved.user_id == "user1"

    def test_invalidate_session(self) -> None:
        auth = AuthManager(self.security_config)
        session = auth.create_session(user_id="user1", role=Role.VIEWER)
        assert auth.invalidate_session(session.id) is True
        assert auth.get_session(session.id) is None

    def test_set_and_verify_password(self) -> None:
        auth = AuthManager(self.security_config)
        auth.set_password("user1", "mypassword")
        assert auth.verify_password("user1", "mypassword") is True
        assert auth.verify_password("user1", "wrong") is False

    def test_has_user(self) -> None:
        auth = AuthManager(self.security_config)
        auth.set_password("user1", "password")
        assert auth.has_user("user1") is True
        assert auth.has_user("unknown") is False

    def test_check_permission(self) -> None:
        auth = AuthManager(self.security_config)
        token = TokenPayload(sub="user1", role=Role.ADMIN, exp=time.time() + 3600)
        assert auth.check_permission(token, "jobs:create") is True
        assert auth.check_permission(token, "users:delete") is True

    def test_require_role(self) -> None:
        auth = AuthManager(self.security_config)
        token = TokenPayload(sub="user1", role=Role.ADMIN, exp=time.time() + 3600)
        assert auth.require_role(token, Role.ADMIN) is True
        assert auth.require_role(token, Role.VIEWER) is False
        assert auth.require_role(token, Role.ADMIN, Role.OPERATOR) is True

    def test_cleanup_expired_sessions(self) -> None:
        auth = AuthManager(self.security_config)
        auth.create_session(user_id="user1", role=Role.VIEWER)
        auth._sessions["expired"] = Session(
            user_id="user2", role=Role.VIEWER, expires_at=time.time() - 10
        )
        removed = auth.cleanup_expired_sessions()
        assert removed >= 1

    def test_max_api_keys(self) -> None:
        self.security_config.api_key.max_keys_per_user = 2
        auth = AuthManager(self.security_config)
        auth.create_api_key(user_id="user1", name="key1")
        auth.create_api_key(user_id="user1", name="key2")
        with pytest.raises(ValueError):
            auth.create_api_key(user_id="user1", name="key3")


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestRateLimiter(SecurityTestBase):
    def test_default_limit(self) -> None:
        limiter = RateLimiter(self.security_config)
        result = limiter.check_rate_limit("192.168.1.1")
        assert result.allowed is True

    def test_bypass_token(self) -> None:
        self.security_config.rate_limit.bypass_tokens = ["internal-token"]
        limiter = RateLimiter(self.security_config)
        result = limiter.check_rate_limit("192.168.1.1", bypass_token="internal-token")
        assert result.allowed is True
        assert result.limit == 999999

    def test_set_endpoint_limit(self) -> None:
        limiter = RateLimiter(self.security_config)
        limiter.set_endpoint_limit("/api/custom", 5)
        for _ in range(5):
            limiter.check_rate_limit("1.2.3.4", endpoint="/api/custom")
        result = limiter.check_rate_limit("1.2.3.4", endpoint="/api/custom")
        assert result.allowed is False

    def test_add_remove_bypass_token(self) -> None:
        limiter = RateLimiter(self.security_config)
        limiter.add_bypass_token("new-token")
        result = limiter.check_rate_limit("1.2.3.4", bypass_token="new-token")
        assert result.allowed is True
        assert limiter.remove_bypass_token("new-token") is True
        assert limiter.remove_bypass_token("nonexistent") is False

    def test_cleanup(self) -> None:
        limiter = RateLimiter(self.security_config)
        limiter.check_rate_limit("1.2.3.4")
        removed = limiter.cleanup()
        assert removed >= 0


@pytest.mark.unit
class TestURLValidator(SecurityTestBase):
    def test_valid_url(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("https://example.com/api")
        assert result.is_valid is True

    def test_empty_url(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("")
        assert result.is_valid is False

    def test_ssrf_localhost(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("http://localhost/admin")
        assert result.is_valid is False

    def test_internal_ip(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("http://192.168.1.1/admin")
        assert result.is_valid is False

    def test_allow_internal(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("http://192.168.1.1/admin", allow_internal=True)
        assert result.is_valid is True

    def test_invalid_scheme(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate("ftp://example.com/file")
        assert result.is_valid is False

    def test_validate_redirect_url_valid(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate_redirect_url("/dashboard", allowed_hosts={"example.com"})
        assert result.is_valid is True

    def test_validate_redirect_url_disallowed(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate_redirect_url("http://evil.com", allowed_hosts={"example.com"})
        assert result.is_valid is False

    def test_validate_redirect_protocol_relative(self) -> None:
        validator = URLValidator(self.security_config)
        result = validator.validate_redirect_url("//evil.com")
        assert result.is_valid is False


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestInputValidator(SecurityTestBase):
    def test_sanitize_string(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.sanitize_string("hello\x00world")
        assert "\x00" not in result

    def test_sanitize_dict(self) -> None:
        validator = InputValidator(self.security_config)
        data = {"key": "value\x00", "nested": {"a": "b"}}
        result = validator.sanitize_dict(data)
        assert "\x00" not in result["key"]

    def test_check_request_size(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.check_request_size(100)
        assert result.is_valid is True

    def test_check_request_size_too_large(self) -> None:
        validator = InputValidator(self.security_config)
        result = validator.check_request_size(100 * 1024 * 1024)
        assert result.is_valid is False


@pytest.mark.unit
class TestJobPayloadValidator(SecurityTestBase):
    def test_valid_payload(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            target_name="test-target",
            mode="idor",
        )
        assert result.is_valid is True

    def test_invalid_mode(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            mode="invalid_mode",
        )
        assert result.is_valid is False

    def test_invalid_modules(self) -> None:
        validator = JobPayloadValidator(self.security_config)
        result = validator.validate(
            base_url="https://example.com/api",
            modules=["valid", "invalid module!"],
        )
        assert result.is_valid is False


@pytest.mark.unit
class TestValidationResult(unittest.TestCase):
    def test_defaults(self) -> None:
        result = ValidationResult()
        assert result.is_valid is True
        assert result.error_message == ""

    def test_with_errors(self) -> None:
        result = ValidationResult(valid=False, errors=["error1", "error2"])
        assert result.is_valid is False
        assert "error1" in result.error_message


@pytest.mark.unit
class TestValidationRule(unittest.TestCase):
    def test_rule_creation(self) -> None:
        rule = ValidationRule(
            name="no_sql_injection",
            pattern=r"(?i)union\s+select",
            error_message="SQL injection detected",
        )
        assert rule.name == "no_sql_injection"
        assert rule.is_blocklist is True


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestSecretManager(SecurityTestBase):
    def test_get_secret(self) -> None:
        manager = SecretManager(self.security_config)
        os.environ["TEST_SECRET"] = "test-value"
        assert manager.get_secret("TEST_SECRET") == "test-value"
        del os.environ["TEST_SECRET"]

    def test_get_secret_default(self) -> None:
        manager = SecretManager(self.security_config)
        assert manager.get_secret("NONEXISTENT_SECRET", "default") == "default"

    def test_get_secret_required(self) -> None:
        manager = SecretManager(self.security_config)
        with pytest.raises(ValueError):
            manager.get_secret_required("NONEXISTENT_SECRET")

    def test_set_secret(self) -> None:
        manager = SecretManager(self.security_config)
        manager.set_secret("MY_SECRET", "value")
        assert manager.get_secret("MY_SECRET") == "value"

    def test_clear_cache(self) -> None:
        manager = SecretManager(self.security_config)
        manager.set_secret("MY_SECRET", "value")
        manager.clear_cache()
        assert manager.get_secret("MY_SECRET") is None

    def test_hash_secret(self) -> None:
        manager = SecretManager(self.security_config)
        hashed = manager.hash_secret("password123")
        assert ":" in hashed

    def test_verify_hashed_secret(self) -> None:
        manager = SecretManager(self.security_config)
        hashed = manager.hash_secret("password123")
        assert manager.verify_hashed_secret("password123", hashed) is True
        assert manager.verify_hashed_secret("wrong", hashed) is False


@pytest.mark.unit
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


@pytest.mark.unit
class TestGenerateFernetKey(unittest.TestCase):
    def test_key_format(self) -> None:
        key = generate_fernet_key()
        assert isinstance(key, str)
        assert len(key) > 0

    def test_keys_are_unique(self) -> None:
        k1 = generate_fernet_key()
        k2 = generate_fernet_key()
        assert k1 != k2

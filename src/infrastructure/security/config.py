"""Centralized security configuration for the pipeline.

Provides a pydantic-based configuration model with environment variable
overrides for all security-related settings including JWT, API keys,
rate limiting, CORS, encryption, and audit logging.

Environment Variables:
    SEC_JWT_SECRET: Secret key for JWT token signing
    SEC_JWT_ALGORITHM: JWT signing algorithm (default: HS256)
    SEC_JWT_ACCESS_EXPIRY_MINUTES: Access token expiry in minutes
    SEC_JWT_REFRESH_EXPIRY_DAYS: Refresh token expiry in days
    SEC_API_KEY_HEADER: Header name for API key authentication
    SEC_SESSION_TIMEOUT_MINUTES: Session inactivity timeout
    SEC_RATE_LIMIT_DEFAULT: Default requests per minute
    SEC_RATE_LIMIT_JOBS: Job creation requests per minute
    SEC_RATE_LIMIT_ADMIN: Admin endpoint requests per minute
    SEC_CORS_ORIGINS: Comma-separated list of allowed origins
    SEC_ENCRYPTION_KEY: Fernet key for data-at-rest encryption
    SEC_AUDIT_LOG_PATH: Path to audit log file
    SEC_AUDIT_RETENTION_DAYS: Days to retain audit logs
    SEC_INTERNAL_SERVICE_TOKENS: Comma-separated tokens for internal services
"""

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


def _env_str(name: str, default: str) -> str:
    """Read a string from environment with a fallback."""
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    """Read an integer from environment with a fallback."""
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError, TypeError:
        return default


def _env_float(name: str, default: float) -> float:
    """Read a float from environment with a fallback."""
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError, TypeError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean from environment with a fallback."""
    val = os.environ.get(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: list[str]) -> list[str]:
    """Read a comma-separated list from environment with a fallback."""
    val = os.environ.get(name)
    if val is None:
        return default
    return [item.strip() for item in val.split(",") if item.strip()]


class JWTConfig(BaseModel):
    """Configuration for JWT token generation and validation."""

    secret: str = Field(
        default=_env_str("SEC_JWT_SECRET", ""),
        description="Secret key for JWT signing. Must be set in production.",
    )
    algorithm: str = Field(default=_env_str("SEC_JWT_ALGORITHM", "HS256"))
    access_token_expiry_minutes: int = Field(
        default=_env_int("SEC_JWT_ACCESS_EXPIRY_MINUTES", 30),
        gt=0,
    )
    refresh_token_expiry_days: int = Field(
        default=_env_int("SEC_JWT_REFRESH_EXPIRY_DAYS", 7),
        gt=0,
    )
    issuer: str = Field(default="cyber-security-pipeline")
    audience: str = Field(default="pipeline-dashboard")


class APIKeyConfig(BaseModel):
    """Configuration for API key management."""

    header_name: str = Field(default=_env_str("SEC_API_KEY_HEADER", "X-API-Key"))
    key_prefix: str = Field(default="csp_")
    min_key_length: int = Field(default=32)
    hash_algorithm: str = Field(default="sha256")
    rotation_days: int = Field(default=90, gt=0)
    max_keys_per_user: int = Field(default=5, gt=0)


class SessionConfig(BaseModel):
    """Configuration for session management."""

    timeout_minutes: int = Field(
        default=_env_int("SEC_SESSION_TIMEOUT_MINUTES", 60),
        gt=0,
    )
    max_sessions_per_user: int = Field(default=3, gt=0)
    cookie_name: str = Field(default="session_id")
    cookie_secure: bool = Field(default=True)
    cookie_httponly: bool = Field(default=True)
    cookie_samesite: str = Field(default="lax")


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""

    default_requests_per_minute: int = Field(
        default=_env_int("SEC_RATE_LIMIT_DEFAULT", 60),
        gt=0,
    )
    jobs_requests_per_minute: int = Field(
        default=_env_int("SEC_RATE_LIMIT_JOBS", 10),
        gt=0,
    )
    admin_requests_per_minute: int = Field(
        default=_env_int("SEC_RATE_LIMIT_ADMIN", 20),
        gt=0,
    )
    replay_requests_per_minute: int = Field(default=30, gt=0)
    window_seconds: int = Field(default=60, gt=0)
    redis_url: str | None = Field(default=None)
    bypass_tokens: list[str] = Field(
        default_factory=lambda: _env_list("SEC_INTERNAL_SERVICE_TOKENS", []),
    )


class CORSConfig(BaseModel):
    """Configuration for Cross-Origin Resource Sharing."""

    allowed_origins: list[str] = Field(
        default_factory=lambda: _env_list(
            "SEC_CORS_ORIGINS",
            ["http://localhost:3000", "http://localhost:5173"],
        ),
    )
    allow_credentials: bool = Field(default=True)
    allowed_methods: list[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    )
    allowed_headers: list[str] = Field(default=["*"])
    max_age: int = Field(default=600, gt=0)
    expose_headers: list[str] = Field(
        default=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-Response-Time",
        ],
    )


class HeadersConfig(BaseModel):
    """Configuration for security HTTP headers."""

    strict_transport_security: str = Field(
        default="max-age=31536000; includeSubDomains",
    )
    content_security_policy: str = Field(
        default=(
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    )
    x_content_type_options: str = Field(default="nosniff")
    x_frame_options: str = Field(default="DENY")
    x_xss_protection: str = Field(default="0")
    referrer_policy: str = Field(default="strict-origin-when-cross-origin")
    permissions_policy: str = Field(
        default="geolocation=(), camera=(), microphone=()",
    )
    cache_control_sensitive: str = Field(
        default="no-store, no-cache, must-revalidate, private",
    )


class EncryptionConfig(BaseModel):
    """Configuration for data encryption."""

    fernet_key: str = Field(
        default=_env_str("SEC_ENCRYPTION_KEY", ""),
        description="Fernet key for symmetric encryption. Generate with encryption.generate_fernet_key().",
    )
    cache_encryption_enabled: bool = Field(default=True)
    api_key_encryption_enabled: bool = Field(default=True)
    tls_min_version: str = Field(default="1.2")
    tls_ciphers: str = Field(
        default="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
    )
    mtls_enabled: bool = Field(default=_env_bool("SEC_MTLS_ENABLED", False))
    tls_certfile: str = Field(default=_env_str("SEC_TLS_CERTFILE", ""))
    tls_keyfile: str = Field(default=_env_str("SEC_TLS_KEYFILE", ""))
    tls_ca_certs: str = Field(default=_env_str("SEC_TLS_CA_CERTS", ""))
    redis_tls_ca_certs: str = Field(default=_env_str("REDIS_TLS_CA_CERTS", ""))
    redis_tls_certfile: str = Field(default=_env_str("REDIS_TLS_CERTFILE", ""))
    redis_tls_keyfile: str = Field(default=_env_str("REDIS_TLS_KEYFILE", ""))


class AuditConfig(BaseModel):
    """Configuration for audit logging."""

    log_path: str = Field(
        default=_env_str(
            "SEC_AUDIT_LOG_PATH",
            str(Path(__file__).resolve().parent.parent / "output" / "audit" / "audit.log"),
        ),
    )
    retention_days: int = Field(
        default=_env_int("SEC_AUDIT_RETENTION_DAYS", 90),
        gt=0,
    )
    tamper_evident: bool = Field(default=True)
    hmac_secret: str = Field(default=_env_str("SEC_AUDIT_HMAC_SECRET", ""))
    export_format: str = Field(default="json")
    max_log_size_mb: int = Field(default=100, gt=0)
    rotate_on_size: bool = Field(default=True)


class InputValidationConfig(BaseModel):
    """Configuration for input validation."""

    max_url_length: int = Field(default=2048, gt=0)
    max_target_name_length: int = Field(default=255, gt=0)
    max_payload_size_bytes: int = Field(default=1 * 1024 * 1024, gt=0)
    max_request_body_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    allowed_url_schemes: list[str] = Field(default=["http", "https"])
    blocked_target_patterns: list[str] = Field(
        default=[
            r"\.\.",
            r"/etc/",
            r"/proc/",
            r"/sys/",
            r"\\",
            r"%00",
            r"<script",
            r"javascript:",
        ],
    )
    allowed_content_types: list[str] = Field(
        default=["application/json", "multipart/form-data"],
    )


class SecurityConfig(BaseModel):
    """Master security configuration for the pipeline.

    Aggregates all security-related sub-configurations into a single
    model with environment variable overrides.

    Attributes:
        jwt: JWT token configuration.
        api_key: API key management configuration.
        session: Session management configuration.
        rate_limit: Rate limiting configuration.
        cors: CORS configuration.
        headers: Security headers configuration.
        encryption: Encryption configuration.
        audit: Audit logging configuration.
        input_validation: Input validation configuration.
    """

    jwt: JWTConfig = Field(default_factory=JWTConfig)
    api_key: APIKeyConfig = Field(default_factory=APIKeyConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    headers: HeadersConfig = Field(default_factory=HeadersConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    input_validation: InputValidationConfig = Field(
        default_factory=InputValidationConfig,
    )

    @field_validator("jwt")
    @classmethod
    def validate_jwt_secret(cls, v: JWTConfig) -> JWTConfig:
        """Warn if JWT secret is empty (development mode only)."""
        if not v.secret:
            import warnings

            warnings.warn(
                "JWT secret is empty. "
                "Set SEC_JWT_SECRET environment variable with a strong random value "
                "(min 32 chars recommended) before deploying to production.",
                UserWarning,
                stacklevel=2,
            )
        return v

    @field_validator("encryption")
    @classmethod
    def validate_fernet_key(cls, v: EncryptionConfig) -> EncryptionConfig:
        """Warn if Fernet key is empty."""
        if not v.fernet_key:
            import warnings

            warnings.warn(
                "Encryption key is not set. Data-at-rest encryption will be disabled. "
                "Set SEC_ENCRYPTION_KEY environment variable.",
                UserWarning,
            )
        return v

    def model_post_init(self, __context: Any) -> None:
        """Ensure audit log directory exists."""
        log_path = Path(self.audit.log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize configuration to a plain dictionary."""
        return self.model_dump()

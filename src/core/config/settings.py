"""Centralized configuration with Pydantic-based settings.

Provides a unified configuration service using pydantic-settings for
automatic environment variable loading, type validation, and 
environment-aware section selection.

Unifies patterns from across the codebase into a single robust structure.
"""

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# AWS EC2 metadata service IP address - used for SSRF protection
AWS_METADATA_IP = "169.254.169.254"

# Maximum request body size in bytes (10 MB)
MAX_REQUEST_BODY_BYTES = 10_485_760

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SETTINGS_PATH = _PROJECT_ROOT / "configs" / "settings.json"


class PipelineSettings(BaseModel):
    """Pipeline execution thresholds, timeouts, and concurrency."""

    http_timeout_seconds: int = 12
    tool_timeout_seconds: int = 120
    retry_attempts: int = 0
    retry_backoff_seconds: float = 1.0
    retry_backoff_multiplier: float = 2.0
    retry_max_backoff_seconds: float = 8.0
    retry_on_timeout: bool = True
    retry_on_error: bool = True
    nuclei_workers: int = 3
    httpx_threads: int = 80
    httpx_batch_size: int = 400
    httpx_batch_concurrency: int = 2
    httpx_fallback_threads: int = 48
    httpx_probe_timeout_seconds: int = 8
    max_collected_urls: int = 1400
    max_live_hosts: int = 12
    max_workers: int = 8
    request_rate_per_second: float = 2.5
    request_burst: float = 1.5
    deep_analysis_top_n: int = 9
    response_diff_limit: int = 10
    idor_compare_limit: int = 8
    behavior_analysis_limit: int = 6
    privilege_escalation_limit: int = 10
    state_transition_limit: int = 10
    parameter_dependency_limit: int = 10
    redirect_chain_limit: int = 8
    auth_boundary_redirect_limit: int = 8


class DashboardSettings(BaseModel):
    """Dashboard server configuration."""

    host: str = "127.0.0.1"
    port: int = 8000
    allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ]
    )
    rate_limit_per_minute: int = 120
    rate_limit_burst: int = 30
    max_request_body_bytes: int = MAX_REQUEST_BODY_BYTES
    log_level: str = "INFO"
    enable_auth: bool = False
    api_key: str = ""


class SecuritySettings(BaseModel):
    """Security-related thresholds and auth settings."""

    severity_scores: dict[str, float] = Field(
        default_factory=lambda: {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        }
    )
    min_confidence_threshold: float = 0.3
    max_severity_display: int = 50
    auth_token_expiry_seconds: int = 3600
    auth_max_failed_attempts: int = 5
    auth_lockout_seconds: int = 300
    ssrf_blocked_suffixes: tuple[str, ...] = (".local", ".internal", ".localhost", ".corp")
    ssrf_cloud_metadata_ip: str = AWS_METADATA_IP


class CacheSettings(BaseModel):
    """Cache sizes and TTLs."""

    probe_cache_enabled: bool = True
    probe_cache_max_entries: int = 5000
    probe_cache_ttl_seconds: int = 300
    response_cache_ttl_hours: int = 24
    api_cache_max_entries: int = 1000
    api_cache_ttl_seconds: int = 60
    settings_cache_ttl_seconds: int = 30


class AppSettings(BaseSettings):
    """Top-level application settings aggregating all sub-settings.

    Automatically loads from environment variables with CYBER_ prefix
    and supports nested configuration via __ delimiter.
    """

    model_config = SettingsConfigDict(
        env_prefix="CYBER_",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = Field(default="development", alias="pipeline_env")
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    dashboard: DashboardSettings = Field(default_factory=DashboardSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)

    # Note: infrastructure.security.config.SecurityConfig is unified here
    # via composition if needed, but for now we maintain the current structure
    # to avoid breaking too many things at once.


def load_settings(path: Path | None = None) -> AppSettings:
    """Load settings with environment-aware section selection and env overrides."""
    env = os.environ.get("PIPELINE_ENV", "development").strip().lower() or "development"
    settings_path = path or _DEFAULT_SETTINGS_PATH

    # Load from JSON if exists
    json_data = {}
    if settings_path.exists():
        try:
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
            defaults = raw.get("defaults", {})
            section = raw.get(env, {})
            json_data = {**defaults, **section}
        except Exception:
            pass

    # Pydantic BaseSettings handles environment overrides automatically
    return AppSettings(**json_data)


_settings_cache: AppSettings | None = None


def get_settings(force_reload: bool = False) -> AppSettings:
    """Return cached AppSettings."""
    global _settings_cache
    if _settings_cache is None or force_reload:
        _settings_cache = load_settings()
    return _settings_cache

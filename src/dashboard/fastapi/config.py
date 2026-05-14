"""Dashboard configuration using pydantic BaseSettings."""

import os
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings


def _resolve_project_root() -> Path:
    """Resolve repository root by scanning parents for pyproject.toml."""
    start = Path(__file__).resolve().parent
    for candidate in [start, *start.parents]:
        if (candidate / "pyproject.toml").exists():
            return candidate
    # Conservative fallback for unexpected layouts.
    return Path(__file__).resolve().parent.parent.parent.parent


_PROJECT_ROOT = _resolve_project_root()
_OUTPUT_ROOT = _PROJECT_ROOT / "output"
_FRONTEND_DIST = _PROJECT_ROOT / "frontend" / "dist"


class DashboardConfig(BaseSettings):
    """Configuration for the FastAPI dashboard server.

    All fields can be overridden via environment variables
    with the ``DASHBOARD_`` prefix.
    """

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    debug: bool = Field(default=False)
    workers: int = Field(default=1)
    output_root: Path = Field(default=_OUTPUT_ROOT)
    workspace_root: Path = Field(default=_PROJECT_ROOT)
    frontend_dist: Path = Field(default=_FRONTEND_DIST)
    config_template: Path = Field(default=_OUTPUT_ROOT / "config_template.json")
    allowed_origins: list[str] = Field(default=["http://localhost:3000", "http://localhost:5173"])
    api_key: str | None = Field(default=None)
    admin_keys: list[str] = Field(default_factory=list)
    rate_limit_jobs: int = Field(default=10)
    rate_limit_replay: int = Field(default=30)
    rate_limit_default: int = Field(default=60)
    log_level: str = Field(default="INFO")
    request_timeout_seconds: int = Field(default=120)
    max_request_body_bytes: int = Field(default=1 * 1024 * 1024)
    redis_url: str | None = Field(default=None)
    security_db_path: str = Field(default=str(_OUTPUT_ROOT / "security_events.db"))
    app_secret_key: str | None = Field(default=None)
    mtls_enabled: bool = Field(default=False)
    tls_certfile: str | None = Field(default=None)
    tls_keyfile: str | None = Field(default=None)
    tls_ca_certs: str | None = Field(default=None)
    storage_config: dict[str, Any] | None = Field(default=None)
    cache_db_path: str = Field(default=str(_OUTPUT_ROOT / "cache" / "cache_layer.db"))
    cache_dir: str = Field(default=str(_OUTPUT_ROOT / "cache" / "files"))
    model_config = {"env_prefix": "DASHBOARD_", "extra": "ignore"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class FeatureFlags:
    """Feature flags for the dashboard.

    Values are read dynamically from environment variables on first access.
    Runtime env var changes are picked up without restart (lazy evaluation).
    """

    @classmethod
    def ENABLE_SSE_PROGRESS(cls) -> bool:
        return os.getenv("ENABLE_SSE_PROGRESS", "true").lower() == "true"

    @classmethod
    def ENABLE_BAYESIAN_ETA(cls) -> bool:
        return os.getenv("ENABLE_BAYESIAN_ETA", "true").lower() == "true"

    @classmethod
    def ENABLE_PLUGIN_PROGRESS(cls) -> bool:
        return os.getenv("ENABLE_PLUGIN_PROGRESS", "true").lower() == "true"

    @classmethod
    def ENABLE_DURATION_FORECAST(cls) -> bool:
        return os.getenv("ENABLE_DURATION_FORECAST", "true").lower() == "true"

    @classmethod
    def ENABLE_FINDINGS_STREAM(cls) -> bool:
        return os.getenv("ENABLE_FINDINGS_STREAM", "true").lower() == "true"

    @classmethod
    def ENABLE_DAG_EXECUTION(cls) -> bool:
        return os.getenv("ENABLE_DAG_EXECUTION", "true").lower() == "true"

    @classmethod
    def ENABLE_API_SECURITY(cls) -> bool:
        return os.getenv("ENABLE_API_SECURITY", "false").lower() == "true"

    @classmethod
    def SSE_HEARTBEAT_INTERVAL_SECONDS(cls) -> int:
        return max(15, min(30, int(os.getenv("SSE_HEARTBEAT_INTERVAL_SECONDS", "25"))))

    @classmethod
    def ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS(cls) -> int:
        return max(1, int(os.getenv("ETA_ENGINE_BACKGROUND_INTERVAL_SECONDS", "5")))

    @classmethod
    def ETA_HISTORICAL_DATA_PATH(cls) -> str:
        return os.getenv("ETA_HISTORICAL_DATA_PATH", "output/eta_history.json")

    @classmethod
    def SSE_MAX_FINDINGS_PER_BATCH(cls) -> int:
        return max(1, int(os.getenv("SSE_MAX_FINDINGS_PER_BATCH", "50")))

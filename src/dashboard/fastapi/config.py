"""Dashboard configuration using pydantic BaseSettings."""

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
    allowed_origins: list[str] = Field(default_factory=list)
    api_key: str | None = Field(default=None)
    admin_keys: list[str] = Field(default_factory=list)
    guest_access_enabled: bool = Field(default=False)
    rate_limit_jobs: int = Field(default=10)
    rate_limit_replay: int = Field(default=30)
    rate_limit_remediation: int = Field(default=5)
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
    model_config = {
        "env_prefix": "DASHBOARD_",
        "extra": "forbid",
        "aliases": {"APP_DEBUG": "debug"},
    }

    def model_post_init(self, __context: Any) -> None:
        """Validate paths after initialization to prevent path traversal."""
        # Validate output_root doesn't escape project root (Finding #182)
        resolved_output = self.output_root.resolve()
        resolved_project = self.workspace_root.resolve()
        if not str(resolved_output).startswith(str(resolved_project)):
            raise ValueError(
                f"output_root must be within the project root. "
                f"Got: {resolved_output}, expected under: {resolved_project}"
            )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

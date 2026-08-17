"""Backend startup script for local development."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

import uvicorn

from src.dashboard.fastapi.app import create_app
from src.dashboard.fastapi.config import DashboardConfig

_PROJECT_ROOT = Path(__file__).resolve().parent


def _validate_environment() -> None:
    secret_key = os.environ.get("APP_SECRET_KEY", "")
    app_env = os.environ.get("APP_ENV", "development")

    if not secret_key:
        print("FATAL: APP_SECRET_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    _DEV_KEY = "change-me-in-production"

    if app_env == "production":
        if secret_key in (_DEV_KEY, ""):
            print(
                "FATAL: APP_SECRET_KEY is set to a development/default value or is empty. "
                "Generate a strong random key (e.g. `openssl rand -hex 32`) and update APP_SECRET_KEY.",
                file=sys.stderr,
            )
            sys.exit(1)

        if os.environ.get("ENABLE_API_SECURITY", "").lower() != "true":
            print(
                "FATAL: ENABLE_API_SECURITY must be 'true' when APP_ENV=production.",
                file=sys.stderr,
            )
            sys.exit(1)

        host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
        if host in ("0.0.0.0", "::"):
            print(
                "WARNING: Binding to 0.0.0.0 in production mode. "
                "Set DASHBOARD_HOST to a specific IP if this is unintended.",
                file=sys.stderr,
            )
    else:
        if secret_key == _DEV_KEY:
            print(
                "WARNING: Using the default development APP_SECRET_KEY. "
                "Generate a unique key for any non-local environment.",
                file=sys.stderr,
            )
        # Allow guest/demo login in local development so the dashboard is usable
        # without pre-creating API keys. Production should opt-in explicitly
        # via DASHBOARD_GUEST_ACCESS_ENABLED if desired.
        os.environ.setdefault("DASHBOARD_GUEST_ACCESS_ENABLED", "true")


def main() -> None:
    _validate_environment()

    config_template = _PROJECT_ROOT / "output" / "config_template.json"
    kwargs: dict = dict(
        output_root=_PROJECT_ROOT / "output",
    )
    if config_template.is_file():
        kwargs["config_template"] = config_template

    config = DashboardConfig(**kwargs)
    app = create_app(config)
    uvicorn.run(
        app,
        host=os.environ.get("DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("DASHBOARD_PORT", "8000")),
        log_level=os.environ.get("APP_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()

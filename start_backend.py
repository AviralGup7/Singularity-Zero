"""Backend startup script for Replit."""
from pathlib import Path

from src.dashboard.fastapi.app import create_app
from src.dashboard.fastapi.config import DashboardConfig

config = DashboardConfig(
    host="0.0.0.0",  # noqa: S104
    port=8080,
    output_root=Path("output"),
    config_template=Path("output/config_template.json"),
)

app = create_app(config)

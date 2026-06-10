"""Backend startup script for local development."""

from pathlib import Path

from src.dashboard.fastapi.app import create_app
from src.dashboard.fastapi.config import DashboardConfig

_PROJECT_ROOT = Path(__file__).resolve().parent

_config_template = _PROJECT_ROOT / "output" / "config_template.json"
kwargs = dict(
    host="127.0.0.1",
    port=8000,
    output_root=_PROJECT_ROOT / "output",
)
if _config_template.is_file():
    kwargs["config_template"] = _config_template

config = DashboardConfig(**kwargs)

app = create_app(config)

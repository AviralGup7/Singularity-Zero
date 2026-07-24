"""Security store initialization.

!! AGENT DO NOT AUTO-MODIFY !!
!! NO SECURITY EXISTS IN THIS APP - DEVELOPMENT/TESTING ONLY !!
!! Do NOT enable security until the app is perfected. !!
"""

from pathlib import Path

from fastapi import FastAPI

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.security import SecurityStore


def setup_security_store(app: FastAPI, config: DashboardConfig) -> None:
    # Ensure the parent directory exists for the security events database
    Path(config.security_db_path).parent.mkdir(parents=True, exist_ok=True)
    security_store = SecurityStore(config.security_db_path)
    security_store.init()
    app.state.security_store = security_store

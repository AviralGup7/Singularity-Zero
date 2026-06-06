"""Security store initialization."""

from fastapi import FastAPI

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.security import SecurityStore


def setup_security_store(app: FastAPI, config: DashboardConfig) -> None:
    security_store = SecurityStore(config.security_db_path)
    security_store.init()
    app.state.security_store = security_store

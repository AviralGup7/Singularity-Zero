"""Router inclusion for the FastAPI dashboard."""

from fastapi import FastAPI

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.routers import api_router


def setup_routers(app: FastAPI, config: DashboardConfig | None = None) -> None:
    app.include_router(api_router)

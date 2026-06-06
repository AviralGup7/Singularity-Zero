"""Router inclusion for the FastAPI dashboard."""

from fastapi import FastAPI

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.routers import api_router
from src.dashboard.fastapi.spa import setup_spa_routes


def setup_routers(app: FastAPI, config: DashboardConfig | None = None) -> None:
    app.include_router(api_router)
    setup_spa_routes(app)

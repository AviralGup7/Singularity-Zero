"""FastAPI application factory for the cyber security dashboard."""

import logging

from src.dashboard.fastapi.app_factory import create_app

logger = logging.getLogger(__name__)

__all__ = ["create_app"]

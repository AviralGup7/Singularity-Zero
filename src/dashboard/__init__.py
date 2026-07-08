"""Dashboard package facade.

Re-exports the ``main`` entry point for the FastAPI dashboard server.
"""

from src.dashboard.fastapi.main import main

__all__ = ["main"]

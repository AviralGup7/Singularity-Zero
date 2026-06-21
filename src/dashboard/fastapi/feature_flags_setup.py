"""Feature flags setup for the FastAPI dashboard."""


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def maybe_start_bayesian_eta(app: FastAPI | None = None) -> None:
    from src.dashboard.eta_engine import get_eta_engine

    eta_engine = get_eta_engine()
    import asyncio

    task = asyncio.create_task(eta_engine.start())
    if app is not None:
        app.state.eta_task = task

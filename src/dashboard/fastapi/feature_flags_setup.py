"""Feature flags setup for the FastAPI dashboard."""


def maybe_start_bayesian_eta(app: object | None = None) -> None:
    from src.dashboard.eta_engine import get_eta_engine

    eta_engine = get_eta_engine()
    import asyncio

    task = asyncio.create_task(eta_engine.start())
    if app is not None:
        app.state.eta_task = task

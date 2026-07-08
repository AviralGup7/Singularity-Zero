"""Feature flags setup for the FastAPI dashboard.

Bug #7: Uses TaskRegistry instead of bare asyncio.create_task() so the
ETA engine startup task is visible to lifecycle management, shutdown,
and status reporting. Previously the task was invisible to
TaskRegistry.status(), shutdown_owner(), and shutdown_all().
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

_eta_startup_task: asyncio.Task[None] | None = None


def maybe_start_bayesian_eta(app: object | None = None) -> None:
    global _eta_startup_task

    if _eta_startup_task is not None and not _eta_startup_task.done():
        logger.debug("ETA engine startup already in progress; skipping")
        return

    from src.dashboard.eta_engine import get_eta_engine

    eta_engine = get_eta_engine()

    async def _supervised_start() -> None:
        try:
            await eta_engine.start()
        except Exception:
            logger.exception("ETA engine startup failed")

    # Bug #7: Register with TaskRegistry so lifecycle management can
    # track, cancel, and report on this task.
    try:
        from src.core.task_registry import get_task_registry

        _eta_startup_task = get_task_registry().create_task(
            _supervised_start(), owner="eta_engine", name="startup"
        )
    except (ImportError, RuntimeError):
        # Fallback if TaskRegistry is not yet initialized (e.g. early import)
        _eta_startup_task = asyncio.create_task(_supervised_start())

    if app is not None:
        app.state.eta_task = _eta_startup_task


def shutdown_bayesian_eta() -> None:
    """Cancel the ETA engine task if running. Safe to call multiple times."""
    global _eta_startup_task
    if _eta_startup_task is not None and not _eta_startup_task.done():
        logger.info("Cancelling ETA engine startup task")
        _eta_startup_task.cancel()
    _eta_startup_task = None

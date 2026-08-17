"""Pipeline progress integration — monkey-patches job_state.apply_progress."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


def integrate_with_pipeline_progress(services: Any) -> None:
    """Hook into pipeline progress events and broadcast via WebSocket.

    Monkey-patches ``src.dashboard.job_state.apply_progress`` so that
    every progress update also emits a WebSocket broadcast.
    """
    try:
        from src.dashboard import job_state
    except (ImportError, ModuleNotFoundError):
        logger.debug("dashboard.job_state not available; skipping pipeline progress integration")
        return

    _orig_apply_progress = getattr(job_state, "apply_progress", None)
    if not callable(_orig_apply_progress):
        logger.debug("apply_progress not found; skipping integration")
        return

    def _do_broadcast_progress(job_id: str, stage: str, percent: int, detail: str = "") -> None:
        try:
            services.broadcast_progress(job_id, stage, percent, detail=detail)
        except Exception as exc:
            logger.debug("WS broadcast progress failed: %s", exc)

    def _do_broadcast_log(job_id: str, line: str, source: str = "stdout") -> None:
        try:
            services.broadcast_log(job_id, line, source=source)
        except Exception as exc:
            logger.debug("WS broadcast log failed: %s", exc)

    def _patched_apply_progress(
        job_id: str,
        stage: str,
        percent: int,
        *,
        detail: str = "",
        log_line: str | None = None,
        **kwargs: Any,
    ) -> Any:
        result = _orig_apply_progress(job_id, stage, percent, detail=detail, **kwargs)
        if asyncio.iscoroutine(result):

            async def _awaited() -> Any:
                val = await result
                _do_broadcast_progress(job_id, stage, percent, detail)
                if log_line:
                    _do_broadcast_log(job_id, log_line)
                return val

            return _awaited()
        else:
            _do_broadcast_progress(job_id, stage, percent, detail)
            if log_line:
                _do_broadcast_log(job_id, log_line)
            return result

    job_state.apply_progress = _patched_apply_progress  # type: ignore[attr-defined]
    logger.debug("Pipeline progress integration installed")

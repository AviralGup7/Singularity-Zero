"""Fatal failure detection utilities for pipeline stage execution.

Provides helpers to evaluate whether stage metrics signal a fatal (non-recoverable)
failure that should halt the entire pipeline run.
"""

from __future__ import annotations

from typing import Any


def _is_truthy_fatal(val: Any) -> bool:
    """Coerce a raw metric value to a definitive True/False fatality flag."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "fatal")
    return bool(val)


def metrics_indicate_fatal_failure(metrics: Any) -> bool:
    """Return True if the given stage metrics dict signals a fatal failure.

    Decision rules (in priority order):
    1. If *status* is ``ok``, ``success``, or ``completed`` → not fatal.
    2. If the ``fatal`` key is explicitly present → honour its truthiness.
    3. If *status* is a known failure code and ``fatal`` is absent → treat as
       fatal so that the recon safety-net fires.
    """
    if not isinstance(metrics, dict):
        return False

    status = str(metrics.get("status", "")).lower()
    if status in ("ok", "success", "completed"):
        return False

    fatal_marker = metrics.get("fatal")
    if fatal_marker is None:
        # If it's a failure (not ok) but fatal is missing, treat as fatal for recon safety
        return status in ("failed", "error", "timeout")

    return _is_truthy_fatal(fatal_marker)

"""Simple observability helpers for the collectors package.

These helpers intentionally mirror the progress callback contract used
throughout the recon code so they can be dropped in later.
"""

from typing import Any


def emit_collection_progress(callback: Any, message: str, percent: int, **meta: object) -> None:
    """Emit progress using the provided callback if present.

    The callback signature tolerated by code here is the same as
    used elsewhere in the project: callback(message, percent, **meta)
    or callback(message, percent).
    """
    if callback:
        try:
            callback(message, percent, **meta)
        except TypeError:
            callback(message, percent)

"""Error classification for retry framework (transient/permanent/unknown)."""

from __future__ import annotations

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class TransientError(Exception):
    """Error that may succeed on retry (e.g. network timeout, 5xx)."""

    def __init__(self, message: str, original: BaseException | None = None) -> None:
        super().__init__(message)
        self.original = original


class PermanentError(Exception):
    """Error that will not succeed on retry (e.g. 4xx, auth failure)."""

    def __init__(self, message: str, original: BaseException | None = None) -> None:
        super().__init__(message)
        self.original = original


class RetryBudgetExhausted(Exception):
    """Raised when the per-stage retry budget is depleted."""


_TRANSIENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionResetError,
    ConnectionAbortedError,
    OSError,
    TransientError,
)

_PERMANENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    PermanentError,
    ValueError,
    TypeError,
    KeyError,
)

_HTTP_TRANSIENT_CODES = {408, 429, 500, 502, 503, 504}
_HTTP_PERMANENT_CODES = {400, 401, 403, 404, 405, 410, 422}


def classify_error(exc: BaseException) -> str:
    """Classify an exception as 'transient', 'permanent', or 'unknown'."""
    if isinstance(exc, _TRANSIENT_EXCEPTIONS):
        return "transient"
    if isinstance(exc, _PERMANENT_EXCEPTIONS):
        return "permanent"
    response = getattr(exc, "response", None)
    status_code = getattr(exc, "status_code", None)
    if status_code is None and response is not None:
        status_code = getattr(response, "status_code", None)

    if status_code is not None:
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            code = None

        if code in _HTTP_TRANSIENT_CODES:
            return "transient"
        if code in _HTTP_PERMANENT_CODES:
            return "permanent"
    return "unknown"

"""In-house URL collectors package.

This package contains provider implementations and an aggregator that
will be used to slowly replace external CLI-based collectors. The
implementation here is intentionally small and iterative.
"""

from . import (
    aggregator,  # noqa: F401
    metrics,  # noqa: F401
    providers,  # noqa: F401
)

__all__ = ["providers", "aggregator", "metrics"]

"""Automated filtering system (re-export shim).

The canonical implementation lives in :mod:`src.core.auto_filters`.  This
module is preserved as a thin re-export so historical import paths such
as ``from src.analysis.automation.auto_filters import AutoFilterEngine``
continue to resolve.  See :mod:`src.core.auto_filters` for the source
of truth and the AND/OR semantics (default AND — correct for inverse
exclude rules).
"""

from src.core.auto_filters import (  # noqa: F401
    AutoFilterEngine,
    FilterRule,
    create_default_security_filters,
)

__all__ = [
    "AutoFilterEngine",
    "FilterRule",
    "create_default_security_filters",
]

"""Root conftest -- pin numpy C-extension in sys.modules.

On Python 3.13+ with numpy 2.x, the multi-phase-init C-extension
``_multiarray_umath`` raises ``ImportError: cannot load module more than
once per process`` when something re-imports numpy after its module was
removed from ``sys.modules``.

A pytest plugin (hypothesis, benchmark, etc.) loads numpy early during
plugin initialisation.  If a subsequent step (e.g. pytest-cov coverage
instrumentation) clears ``sys.modules`` entries, the C-extension state
persists in the process but numpy is no longer findable -- causing a
fatal double-load on the next ``import numpy``.

This conftest replaces ``sys.modules`` with a thin dict subclass that
refuses to delete or pop numpy-prefixed keys.  The replacement happens
at module level (before any hook) so it takes effect before plugins run.
"""

from __future__ import annotations

import sys
import types
from typing import Any


class _NumpyGuardedModules(dict[str, types.ModuleType]):  # type: ignore[type-arg]
    """sys.modules subclass that prevents deletion of numpy modules."""

    def __delitem__(self, key: str) -> None:
        if key.startswith("numpy"):
            return
        super().__delitem__(key)

    def pop(self, key: str, *args: Any) -> types.ModuleType:  # type: ignore[override]
        if key.startswith("numpy") and key in self:
            return super().__getitem__(key)
        return super().pop(key, *args)  # type: ignore[return-value]


sys.modules = _NumpyGuardedModules(sys.modules)  # type: ignore[assignment]

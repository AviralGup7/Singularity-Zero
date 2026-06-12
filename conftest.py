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

This conftest installs a ``sys.modules`` guard that prevents numpy
modules from being deleted once they are loaded.  The guard is installed
at module level (before any hook) so it takes effect before plugins run.
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Guard sys.modules: once a numpy module is loaded, prevent its removal.
# This stops the C-extension double-load error on Python 3.13+.
# ---------------------------------------------------------------------------
_real_delitem = sys.modules.__delitem__
_real_pop = sys.modules.pop


def _guarded_delitem(key: object) -> None:
    if isinstance(key, str) and key.startswith("numpy"):
        return  # refuse to delete
    _real_delitem(key)


def _guarded_pop(key: object, *args: object) -> object:  # type: ignore[override]
    if isinstance(key, str) and key.startswith("numpy"):
        if key in sys.modules:
            return sys.modules[key]
        if args:
            return args[0]
        raise KeyError(key)
    return _real_pop(key, *args)


sys.modules.__delitem__ = _guarded_delitem  # type: ignore[assignment]
sys.modules.pop = _guarded_pop  # type: ignore[assignment]

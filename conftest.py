"""Root conftest -- pin numpy C-extension before test collection.

On Python 3.13+ with numpy 2.x, the multi-phase-init C-extension
``_multiarray_umath`` raises ``ImportError: cannot load module more than
once per process`` when pytest's ``_import_module_using_spec`` creates
fresh module namespaces.

Importing numpy at pytest_configure time (earliest hook) pins it in
``sys.modules`` so every later ``import numpy`` resolves to the cached
module without re-loading the C-extension.
"""

from __future__ import annotations

import sys


def pytest_configure(config):  # type: ignore[no-untyped-def]
    """Import numpy once before any test collection begins."""
    import numpy  # noqa: F401

    # Also pre-import critical sub-modules to prevent partial-load races.
    for _sub in ("numpy.core", "numpy._core"):
        if _sub not in sys.modules:
            try:
                __import__(_sub)
            except Exception:
                pass

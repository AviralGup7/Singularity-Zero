"""Root conftest – force critical C-extension imports before test collection.

On Python 3.13+ with numpy 2.x, the C-extension ``_multiarray_umath`` uses
multi-phase init.  If it is loaded through *two* different module-resolution
paths (easy to trigger with ``--import-mode=importlib`` and a package-style
``src.`` tree), Python raises:

    ImportError: cannot load module more than once per process

Importing numpy once here – before pytest touches *any* test module – pins
it in ``sys.modules`` under a single identity so every subsequent
``import numpy`` inside test code finds the already-loaded module.
"""

from __future__ import annotations

import importlib
import sys

for _mod in ("numpy", "numpy.core", "numpy._core"):
    if _mod not in sys.modules:
        try:
            importlib.import_module(_mod)
        except ImportError:
            pass

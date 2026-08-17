"""Root conftest -- shared pytest configuration for all test suites."""

import os
import sys
from pathlib import Path

# Ensure src is on the path for test discovery
_src = Path(__file__).resolve().parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

try:
    from hypothesis import settings

    settings.register_profile("ci", max_examples=20, deadline=None)
    settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))
except ImportError:
    pass

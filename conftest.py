"""Root conftest -- shared pytest configuration for all test suites."""
import sys
from pathlib import Path

# Ensure src is on the path for test discovery
_src = Path(__file__).resolve().parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

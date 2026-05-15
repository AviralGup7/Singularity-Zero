"""Backward-compatible shim for `src.analysis.passive.detector_idor`.

Older code and tests import `src.analysis.passive.detector_idor` — detectors
were moved into the `detectors` subpackage. Re-export the primary
symbol to preserve the public import path.
"""

from src.analysis.passive.detectors.detector_idor import idor_candidate_finder

__all__ = ["idor_candidate_finder"]

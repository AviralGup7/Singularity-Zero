"""Backward-compatible shim for SSRF detector."""

from src.analysis.passive.detectors.detector_ssrf import ssrf_candidate_finder

__all__ = ["ssrf_candidate_finder"]

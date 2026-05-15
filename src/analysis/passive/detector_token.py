"""Backward-compatible shim for token leak detector."""

from src.analysis.passive.detectors.detector_token import token_leak_detector

__all__ = ["token_leak_detector"]

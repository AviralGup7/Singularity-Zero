"""Backward-compatible shim for vulnerable components detector."""

from src.analysis.passive.detectors.detector_vulnerable_components import (
    vulnerable_component_detector,
)

__all__ = ["vulnerable_component_detector"]

"""Matrix of scan mode × detector family coverage."""

from __future__ import annotations

from src.detection.bundle import bundle_for
from src.jobs.modes import mode_keys


def mode_matrix() -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    for key in mode_keys():
        matrix[key] = bundle_for(key).families()
    return matrix


def mode_sizes() -> dict[str, int]:
    return {key: bundle_for(key).size for key in mode_keys()}

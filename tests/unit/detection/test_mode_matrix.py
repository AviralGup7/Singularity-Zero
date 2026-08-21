from __future__ import annotations

from src.detection.mode_matrix import mode_matrix, mode_sizes


def test_every_mode_has_detectors() -> None:
    sizes = mode_sizes()
    assert sizes["full"] >= sizes["idor"]
    assert mode_matrix()["standard"]

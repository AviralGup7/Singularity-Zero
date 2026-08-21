from __future__ import annotations

from src.detection.bundle import bundle_for


def test_standard_bundle_is_non_empty() -> None:
    bundle = bundle_for("standard")
    assert bundle.size >= 1
    assert bundle.families()

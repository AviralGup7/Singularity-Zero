from __future__ import annotations

from src.jobs.artifacts import ArtifactKind, default_launcher_artifacts
from src.reporting.severity_map import at_least, normalize_severity


def test_normalize_and_floor() -> None:
    assert normalize_severity("crit") == "critical"
    assert normalize_severity("informational") == "info"
    assert at_least("high", "medium")
    assert not at_least("low", "high")


def test_default_artifacts() -> None:
    index = default_launcher_artifacts("abc123", "target")
    kinds = {item.kind for item in index.items}
    assert ArtifactKind.CONFIG in kinds
    assert ArtifactKind.REPORT in kinds
    assert index.to_dict()["count"] == 5

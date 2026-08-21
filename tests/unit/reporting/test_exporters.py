from __future__ import annotations

from src.reporting.exporters import list_exporter_platforms


def test_exporter_platforms_include_bug_bounty_targets() -> None:
    platforms = list_exporter_platforms()
    assert "hackerone" in platforms
    assert "bugcrowd" in platforms
    assert "base" not in platforms

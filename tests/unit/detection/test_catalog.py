from __future__ import annotations

from src.detection.catalog import finding_spec_count, list_finding_spec_keys


def test_finding_spec_catalog_covers_the_spec_dump() -> None:
    keys = list_finding_spec_keys()
    assert finding_spec_count() >= 80
    assert "cors_misconfig" in keys
    assert "sqli_safe" in keys
    assert "__init__" not in keys

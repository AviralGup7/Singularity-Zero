"""Coverage for compliance category mapping."""

from __future__ import annotations

import pytest

from src.reporting.compliance_mapping import (
    _normalize_category,
    map_finding_to_compliance,
)


@pytest.mark.unit
def test_map_finding_is_case_and_separator_insensitive() -> None:
    titled = map_finding_to_compliance("SQL Injection")
    dashed = map_finding_to_compliance("sql-injection")
    snake = map_finding_to_compliance("sql_injection")
    assert titled == dashed == snake
    assert "A03:2021-Injection" in titled["OWASP Top 10 (2021)"]
    assert "6.2.4" in titled["PCI DSS v4.0"]
    assert titled["MITRE ATT&CK"] == ["T1190"]


@pytest.mark.unit
def test_unknown_category_returns_empty_lists() -> None:
    mapped = map_finding_to_compliance("not_a_real_category")
    assert mapped
    assert all(values == [] for values in mapped.values())


@pytest.mark.unit
def test_idor_maps_to_access_control_and_api_top_10() -> None:
    mapped = map_finding_to_compliance("IDOR")
    assert "A01:2021-Broken Access Control" in mapped["OWASP Top 10 (2021)"]
    assert "API01:2023" in mapped["OWASP API Security Top 10"]
    assert _normalize_category(" Broken Access Control ") == "broken_access_control"

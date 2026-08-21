from __future__ import annotations

from src.analysis.checks.registry import list_active_checks, list_all_checks, list_passive_checks


def test_checks_index_lists_both_trees() -> None:
    active = list_active_checks()
    passive = list_passive_checks()
    assert "access_control_analyzer" in active or "idor_probe" in active
    assert list_all_checks()
    assert set(active).issubset(set(list_all_checks()))
    assert isinstance(passive, tuple)

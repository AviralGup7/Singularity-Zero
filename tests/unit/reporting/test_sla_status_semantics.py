"""SLA trending must not treat verified findings as remediated."""

from __future__ import annotations

from src.reporting.sla_tracker import (
    CONFIRMED_OPEN_STATUSES,
    REMEDIATED_STATUSES,
    is_remediated_status,
)


def test_verified_and_verified_tp_are_not_remediated() -> None:
    assert is_remediated_status("verified") is False
    assert is_remediated_status("verified_tp") is False
    assert is_remediated_status("VERIFIED") is False
    assert "verified" in CONFIRMED_OPEN_STATUSES
    assert "verified_tp" in CONFIRMED_OPEN_STATUSES
    assert "verified" not in REMEDIATED_STATUSES


def test_remediated_aliases() -> None:
    for status in ("remediated", "resolved", "fixed", "closed", "REMEDIATED"):
        assert is_remediated_status(status) is True


def test_open_and_false_positive_are_not_remediated() -> None:
    for status in (
        "active",
        "open",
        "unremediated",
        "candidate",
        "false_positive",
        "",
        None,
    ):
        assert is_remediated_status(status) is False

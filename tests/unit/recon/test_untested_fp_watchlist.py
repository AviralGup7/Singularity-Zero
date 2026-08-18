"""Coverage for previously untested false-positive regression watchlist."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.recon.fp_watchlist import (
    FPWatchlistManager,
    _build_url_pattern,
    _extract_finding_id,
    _extract_severity,
    _extract_url,
    _extract_vulnerability_class,
    _is_false_positive,
    _match_reemergence,
    fnmatch_url,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "finding",
    [
        {"status": "False_Positive"},
        {"lifecycle_state": "false_positive"},
        {"decision": "DROP"},
        {"fp_reason": "waf noise"},
        {"is_false_positive": True},
    ],
)
def test_is_false_positive_true(finding: dict[str, object]) -> None:
    assert _is_false_positive(finding) is True


@pytest.mark.unit
def test_is_false_positive_false_for_real_finding() -> None:
    assert _is_false_positive({"status": "open", "severity": "high"}) is False
    assert _is_false_positive({"is_false_positive": False}) is False


@pytest.mark.unit
def test_extract_finding_id_prefers_explicit_then_hashes() -> None:
    assert _extract_finding_id({"id": "  abc  "}) == "abc"
    assert _extract_finding_id({"finding_id": "f-1"}) == "f-1"
    hashed = _extract_finding_id({"url": "https://x", "type": "xss"})
    assert len(hashed) == 16
    assert hashed == _extract_finding_id({"type": "xss", "url": "https://x"})


@pytest.mark.unit
def test_extract_url_class_and_severity_defaults() -> None:
    assert _extract_url({"target": "https://a/b"}) == "https://a/b"
    assert _extract_url({}) == ""
    assert _extract_vulnerability_class({"category": "XSS"}) == "xss"
    assert _extract_vulnerability_class({}) == "unknown"
    assert _extract_severity({"severity": "HIGH"}) == "high"
    assert _extract_severity({}) == "info"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("", "*"),
        ("https://ex.com/a/b?x=1#frag", "https://ex.com/a/b*"),
        ("ex.com/account", "https://ex.com/account*"),
    ],
)
def test_build_url_pattern(url: str, expected: str) -> None:
    assert _build_url_pattern(url) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "pattern", "expected"),
    [
        ("https://ex.com/a/b", "https://ex.com/a/b", True),
        ("https://ex.com/a/b?x=1", "https://ex.com/a/b*", True),
        ("HTTPS://EX.COM/A/B", "https://ex.com/a/b", True),
        ("https://ex.com/a/c", "https://ex.com/a/b", False),
        ("aXexample.com", "*.example.com", False),
        ("foo.example.com", "*.example.com", True),
    ],
)
def test_fnmatch_url(url: str, pattern: str, expected: bool) -> None:
    assert fnmatch_url(url, pattern) is expected


@pytest.mark.unit
def test_match_reemergence_requires_class_and_skips_remediated() -> None:
    entry = {
        "vulnerability_class": "xss",
        "url_pattern": "https://ex.com/a*",
        "status": "monitoring",
    }
    assert _match_reemergence(entry, {"type": "xss", "url": "https://ex.com/a/1"}) is True
    assert _match_reemergence(entry, {"type": "sqli", "url": "https://ex.com/a/1"}) is False
    remediating = {**entry, "status": "resolved"}
    assert _match_reemergence(remediating, {"type": "xss", "url": "https://ex.com/a/1"}) is False


@pytest.mark.unit
def test_serialize_load_and_reemergence(tmp_path: Path) -> None:
    manager = FPWatchlistManager()
    findings = [
        {
            "id": "fp-1",
            "status": "false_positive",
            "url": "https://ex.com/account",
            "type": "xss",
            "severity": "medium",
            "fp_reason": "reflected in title",
        },
        {"id": "real-1", "status": "open", "url": "https://ex.com/other", "type": "sqli"},
    ]
    path = manager.serialize_from_findings(findings, tmp_path)
    assert path.name == "regression-watchlist.json"
    loaded = manager.load_watchlist()
    assert len(loaded) == 1
    assert loaded[0]["finding_id"] == "fp-1"
    assert loaded[0]["status"] == "monitoring"

    # Second serialize must not duplicate the same finding.
    manager.serialize_from_findings(findings, tmp_path)
    assert len(manager.load_watchlist()) == 1

    reemerged = manager.check_reemergence(
        [{"id": "new-1", "type": "xss", "url": "https://ex.com/account/profile"}]
    )
    assert len(reemerged) == 1
    assert manager.get_watchlist_urls() == ["https://ex.com/account*"]


@pytest.mark.unit
def test_load_watchlist_missing_or_invalid_returns_empty(tmp_path: Path) -> None:
    manager = FPWatchlistManager()
    assert manager.load_watchlist() == []
    bad = tmp_path / "regression-watchlist.json"
    bad.write_text("{not-json", encoding="utf-8")
    assert manager.load_watchlist(bad) == []
    bad.write_text('{"not": "a-list"}', encoding="utf-8")
    assert manager.load_watchlist(bad) == []


@pytest.mark.unit
def test_get_watchlist_urls_skips_non_monitoring(tmp_path: Path) -> None:
    path = tmp_path / "regression-watchlist.json"
    path.write_text(
        """
        [
          {"url_pattern": "https://a/*", "status": "monitoring"},
          {"url_pattern": "https://A/*", "status": "monitoring"},
          {"url_pattern": "https://b/*", "status": "resolved"}
        ]
        """,
        encoding="utf-8",
    )
    manager = FPWatchlistManager(watchlist_path=path)
    assert manager.get_watchlist_urls() == ["https://a/*"]

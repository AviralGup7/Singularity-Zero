"""Tests for finding deduplication engine."""

from __future__ import annotations

from src.learning.finding_deduplicator import FindingDeduplicator, FindingGroup


class TestFindingDeduplicator:
    """Unit tests for FindingDeduplicator."""

    def setup_method(self) -> None:
        self.dedup = FindingDeduplicator()

    def test_empty_findings(self) -> None:
        unique, groups = self.dedup.deduplicate([])
        assert unique == []
        assert groups == []
        summary = self.dedup.get_dedup_summary()
        assert summary["unique_findings"] == 0
        assert summary["duplicate_groups"] == 0
        assert summary["total_duplicates_removed"] == 0

    def test_single_finding(self) -> None:
        findings = [{"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"}]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 0

    def test_identical_findings_deduplicated(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"},
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"},
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1
        assert groups[0].count == 3
        assert "https://example.com/a" in groups[0].urls_affected

    def test_different_findings_not_deduplicated(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"},
            {"type": "xss", "title": "Stored XSS", "url": "https://example.com/b"},
            {
                "type": "ssrf",
                "title": "Server-Side Request Forgery",
                "url": "https://example.com/c",
            },
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 3
        assert len(groups) == 0

    def test_same_type_same_url_different_params_not_deduplicated(self) -> None:
        findings = [
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "parameter": "q",
            },
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "parameter": "search",
            },
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 2
        assert len(groups) == 0

    def test_dedup_metadata_added(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"},
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/a"},
        ]
        unique, _ = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert unique[0]["_dedup_count"] == 2
        assert "https://example.com/a" in unique[0]["_urls_affected"]

    def test_dedup_summary(self) -> None:
        findings = [
            {"type": "xss", "title": "XSS #1", "url": "https://example.com/a"},
            {"type": "xss", "title": "XSS #1", "url": "https://example.com/a"},
            {"type": "xss", "title": "XSS #1", "url": "https://example.com/a"},
            {"type": "ssrf", "title": "SSRF #1", "url": "https://example.com/b"},
            {"type": "ssrf", "title": "SSRF #1", "url": "https://example.com/b"},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 2
        assert len(groups) == 2

        summary = self.dedup.get_dedup_summary()
        assert summary["unique_findings"] == 2
        assert summary["duplicate_groups"] == 2
        assert summary["total_duplicates_removed"] == 3

    def test_fingerprint_ignores_irrelevant_fields(self) -> None:
        findings = [
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "severity": "high",
                "confidence": 0.9,
            },
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "severity": "low",
                "confidence": 0.3,
            },
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1

    def test_parameter_included_in_fingerprint(self) -> None:
        findings = [
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "parameter": "q",
            },
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "parameter": "search",
            },
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 2
        assert len(groups) == 0

    def test_method_included_in_fingerprint(self) -> None:
        findings = [
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "method": "GET",
            },
            {
                "type": "xss",
                "title": "Reflected XSS",
                "url": "https://example.com/a",
                "method": "POST",
            },
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 2
        assert len(groups) == 0

    def test_url_normalization_strips_query_params(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/path?q=1"},
            {"type": "xss", "title": "Reflected XSS", "url": "https://example.com/path?q=2"},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1

    def test_endpoint_field_used_as_fallback(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "endpoint": "https://example.com/a"},
            {"type": "xss", "title": "Reflected XSS", "endpoint": "https://example.com/a"},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1

    def test_target_field_used_as_fallback(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "target": "https://example.com/a"},
            {"type": "xss", "title": "Reflected XSS", "target": "https://example.com/a"},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1

    def test_invalid_url_handled_gracefully(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "url": "not-a-url"},
            {"type": "xss", "title": "Reflected XSS", "url": "not-a-url"},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1

    def test_non_string_url_handled(self) -> None:
        findings = [
            {"type": "xss", "title": "Reflected XSS", "url": 123},
            {"type": "xss", "title": "Reflected XSS", "url": 123},
        ]
        unique, groups = self.dedup.deduplicate(findings)
        assert len(unique) == 1
        assert len(groups) == 1

    def test_finding_group_dataclass(self) -> None:
        rep = {"type": "xss", "title": "XSS"}
        group = FindingGroup(
            representative=rep,
            duplicates=[{"type": "xss", "title": "XSS"}],
            count=2,
            urls_affected=["https://example.com/a"],
        )
        assert group.representative == rep
        assert len(group.duplicates) == 1
        assert group.count == 2
        assert "https://example.com/a" in group.urls_affected

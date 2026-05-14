"""Automated finding deduplication engine.

Removes duplicate findings based on multiple criteria.
Runs automatically before report generation.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class FindingGroup:
    """A group of duplicate findings."""

    representative: dict[str, Any]
    duplicates: list[dict[str, Any]] = field(default_factory=list)
    count: int = 1
    urls_affected: list[str] = field(default_factory=list)


class FindingDeduplicator:
    """Automatically deduplicates findings using multiple strategies."""

    def __init__(self) -> None:
        self._groups: list[FindingGroup] = []

    def deduplicate(
        self, findings: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[FindingGroup]]:
        """Deduplicate findings and return unique findings + duplicate groups.

        Returns:
            Tuple of (unique_findings, duplicate_groups)
        """
        seen_hashes: dict[str, FindingGroup] = {}
        unique_findings: list[dict[str, Any]] = []

        for finding in findings:
            fingerprint = self._generate_fingerprint(finding)

            if fingerprint in seen_hashes:
                # Duplicate found
                group = seen_hashes[fingerprint]
                group.duplicates.append(finding)
                group.count += 1

                # Track affected URLs
                url = finding.get("url", finding.get("target", ""))
                if url and url not in group.urls_affected:
                    group.urls_affected.append(url)
            else:
                # New unique finding
                group = FindingGroup(
                    representative=finding,
                    urls_affected=[finding.get("url", finding.get("target", ""))],
                )
                seen_hashes[fingerprint] = group
                unique_findings.append(finding)

        self._groups = [g for g in seen_hashes.values() if g.count > 1]

        # Add dedup metadata to unique findings
        for finding in unique_findings:
            fingerprint = self._generate_fingerprint(finding)
            matching_group = seen_hashes.get(fingerprint)
            if matching_group and matching_group.count > 1:
                finding["_dedup_count"] = matching_group.count
                finding["_urls_affected"] = matching_group.urls_affected

        return unique_findings, self._groups

    def _generate_fingerprint(self, finding: dict[str, Any]) -> str:
        """Generate a fingerprint for a finding based on key attributes."""
        # Use type, title, and endpoint as primary dedup keys
        key_parts = [
            finding.get("type", "").lower(),
            finding.get("title", "").lower(),
            finding.get("endpoint", "").lower(),
            finding.get("parameter", "").lower(),
            finding.get("method", "").upper(),
        ]

        # Normalize URL to domain+path (without query params)
        url = finding.get("url", finding.get("target", ""))
        if url:
            try:
                parsed = urlparse(url)
                normalized_url = f"{parsed.netloc}{parsed.path}"
                key_parts.append(normalized_url.lower())
            except Exception:
                key_parts.append(url.lower())

        key_string = "|".join(key_parts)
        # Use SHA-256 for deterministic, collision-resistant fingerprints.
        return hashlib.sha256(key_string.encode("utf-8")).hexdigest()

    def get_dedup_summary(self) -> dict[str, Any]:
        """Get deduplication summary."""
        total_duplicates = sum(g.count - 1 for g in self._groups)

        return {
            "unique_findings": len([g for g in self._groups]) + 0,  # Will be set externally
            "duplicate_groups": len(self._groups),
            "total_duplicates_removed": total_duplicates,
            "groups": [
                {
                    "type": g.representative.get("type", ""),
                    "title": g.representative.get("title", ""),
                    "count": g.count,
                    "urls_affected": g.urls_affected[:10],  # Limit for report
                }
                for g in self._groups[:20]  # Top 20 groups
            ],
        }

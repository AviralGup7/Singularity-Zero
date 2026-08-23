"""Correlate findings with IOC verdicts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.intel.aggregator import FeedAggregator, LookupResult
from src.intel.ioc import extract_indicators, related_indicators
from src.intel.verdict import Verdict


@dataclass(frozen=True, slots=True)
class FindingIntel:
    finding_id: str
    verdict: Verdict
    indicators: tuple[str, ...]
    votes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "indicators": list(self.indicators),
            "votes": self.votes,
        }


def _finding_blob(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("id") or ""),
        str(finding.get("title") or ""),
        str(finding.get("url") or finding.get("endpoint") or ""),
        str(finding.get("evidence") or ""),
        str(finding.get("description") or ""),
    ]
    return " ".join(parts)


def correlate_finding(finding: dict[str, Any], aggregator: FeedAggregator) -> FindingIntel:
    finding_id = str(finding.get("id") or finding.get("title") or "finding")
    indicators = extract_indicators(_finding_blob(finding))
    expanded = [item for indicator in indicators for item in related_indicators(indicator)]
    results: list[LookupResult] = [aggregator.lookup(item) for item in expanded]
    votes = sum(len(result.votes) for result in results)
    verdict = Verdict.UNKNOWN
    for result in results:
        if result.verdict is Verdict.MALICIOUS:
            verdict = Verdict.MALICIOUS
            break
        if result.verdict is Verdict.SUSPICIOUS:
            verdict = Verdict.SUSPICIOUS
    return FindingIntel(
        finding_id=finding_id,
        verdict=verdict,
        indicators=tuple(item.normalized() for item in indicators),
        votes=votes,
    )


def correlate_findings(
    findings: list[dict[str, Any]], aggregator: FeedAggregator
) -> list[FindingIntel]:
    return [correlate_finding(item, aggregator) for item in findings]


def malicious_ids(rows: list[FindingIntel]) -> list[str]:
    return [row.finding_id for row in rows if row.verdict is Verdict.MALICIOUS]

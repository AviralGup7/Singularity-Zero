"""Render a plain-text intel summary for a job."""

from __future__ import annotations

from src.intel.aggregator import FeedAggregator
from src.intel.correlation import correlate_findings
from src.intel.verdict import Verdict


def render_intel_report(findings: list[dict], aggregator: FeedAggregator) -> str:
    rows = correlate_findings(findings, aggregator)
    lines = [f"intel findings={len(rows)}"]
    malicious = [row for row in rows if row.verdict is Verdict.MALICIOUS]
    suspicious = [row for row in rows if row.verdict is Verdict.SUSPICIOUS]
    lines.append(f"malicious={len(malicious)} suspicious={len(suspicious)}")
    for row in rows:
        if row.verdict is Verdict.UNKNOWN:
            continue
        lines.append(f"- {row.finding_id} {row.verdict.value} indicators={len(row.indicators)}")
    return "\n".join(lines)

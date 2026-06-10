"""Bug bounty report templates.

Generates platform-specific report payloads (HackerOne, Bugcrowd) from
internal finding representations.  No external API calls are made; the
payloads are returned as dictionaries so callers can persist or submit
them at their discretion.
"""

from __future__ import annotations

from typing import Any


class ReportTemplate:
    @staticmethod
    def format_hackerone(finding: dict[str, Any], program: str) -> dict[str, Any]:
        return {
            "program": program,
            "vulnerability_type": str(
                finding.get("vuln_type")
                or finding.get("category")
                or finding.get("title")
                or "Other"
            ),
            "title": str(
                finding.get("title")
                or finding.get("name")
                or finding.get("vuln_type")
                or "Untitled Report"
            ),
            "description": str(finding.get("description") or finding.get("summary") or ""),
            "severity": str(finding.get("severity") or "medium").lower(),
            "target_url": str(
                finding.get("target_url") or finding.get("affected_url") or finding.get("url") or ""
            ),
            "affected_urls": list(
                {
                    u.strip()
                    for u in (
                        finding.get("affected_urls")
                        or [finding.get("affected_url") or finding.get("url", "")]
                    )
                    if u.strip()
                }
            ),
            "evidence": dict(finding.get("evidence") or {}),
            "cvss_score": finding.get("cvss_score"),
            "cwe_id": finding.get("cwe_id"),
            "references": list(finding.get("references") or []),
            "reproduction_steps": str(
                finding.get("reproduction_steps") or finding.get("steps_to_reproduce") or ""
            ),
        }

    @staticmethod
    def format_bugcrowd(finding: dict[str, Any], program: str) -> dict[str, Any]:
        return {
            "program": program,
            "vulnerability_type": str(
                finding.get("vuln_type")
                or finding.get("category")
                or finding.get("title")
                or "Other"
            ),
            "title": str(
                finding.get("title")
                or finding.get("name")
                or finding.get("vuln_type")
                or "Untitled Report"
            ),
            "description": str(finding.get("description") or finding.get("summary") or ""),
            "severity": str(finding.get("severity") or "medium").lower(),
            "target_url": str(
                finding.get("target_url") or finding.get("affected_url") or finding.get("url") or ""
            ),
            "affected_urls": list(
                {
                    u.strip()
                    for u in (
                        finding.get("affected_urls")
                        or [finding.get("affected_url") or finding.get("url", "")]
                    )
                    if u.strip()
                }
            ),
            "evidence": dict(finding.get("evidence") or {}),
            "cvss_score": finding.get("cvss_score"),
            "cwe_id": finding.get("cwe_id"),
            "reproduction_steps": str(
                finding.get("reproduction_steps") or finding.get("steps_to_reproduce") or ""
            ),
            "priority": _bugcrowd_priority(str(finding.get("severity") or "medium").lower()),
        }


def _bugcrowd_priority(severity: str) -> str:
    mapping = {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "info": "P5",
    }
    return mapping.get(severity, "P3")

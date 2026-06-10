"""Context formatting helpers for LLM service payload construction.

Extracted from ``src.intelligence.ml.llm_service`` to keep prompt
construction concerns out of the transport and fallback logic.
"""

from __future__ import annotations


def truncate_context(text: str, max_chars: int = 4000) -> str:
    """Truncate context to fit within LLM token limits safely."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + "\n[... TRUNCATED ...]\n" + text[-half:]


def render_user_prompt_explain(finding: dict, *, truncate: int = 2000) -> str:
    title = finding.get("title") or finding.get("type") or "Vulnerability"
    severity = finding.get("severity") or "medium"
    url = finding.get("url") or finding.get("target") or ""
    desc = finding.get("description") or ""
    evidence = finding.get("evidence") or ""
    return (
        f"Finding: {title}\n"
        f"Severity: {severity}\n"
        f"URL: {url}\n"
        f"Description: {desc}\n"
        f"Captured Evidence: {truncate_context(str(evidence), truncate)}"
    )


def render_user_prompt_patch(finding: dict, *, truncate: int = 2000) -> str:
    title = finding.get("title") or finding.get("type") or "Vulnerability"
    category = finding.get("category") or "general"
    url = finding.get("url") or ""
    evidence = finding.get("evidence") or ""
    request_payload = finding.get("request_payload") or finding.get("payload") or "N/A"
    response_body = finding.get("response_body") or finding.get("response") or ""
    return (
        f"Finding Category: {category}\n"
        f"Vulnerability Title: {title}\n"
        f"URL: {url}\n"
        f"Injected Payload/Evidence: {truncate_context(str(evidence), 1000)}\n"
        f"Original Request Payload: {truncate_context(str(request_payload), 1000)}\n"
        f"Target Response Body snippet: {truncate_context(str(response_body), truncate)}"
    )


def render_user_prompt_triage(finding: dict, *, truncate: int = 4000) -> str:
    title = finding.get("title") or finding.get("type") or "Vulnerability"
    category = finding.get("category") or "general"
    url = finding.get("url") or ""
    evidence = finding.get("evidence") or ""
    request_payload = finding.get("request_payload") or "N/A"
    response_body = finding.get("response_body") or ""
    return (
        f"Finding: {title} ({category})\n"
        f"Target URL: {url}\n"
        f"Scan Evidence: {truncate_context(str(evidence), 1000)}\n"
        f"Request Payload: {truncate_context(str(request_payload), 1000)}\n"
        f"Target Response Body: {truncate_context(str(response_body), truncate)}"
    )


def render_user_prompt_summary(findings: list[dict], compliance_report: dict | None = None) -> str:
    critical_count = sum(
        1 for f in findings if str(f.get("severity", "info")).lower() == "critical"
    )
    high_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "high")
    med_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "medium")
    low_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "low")
    return (
        f"Total Findings: {len(findings)}\n"
        f"Severity breakdown: Critical={critical_count}, High={high_count}, Medium={med_count}, Low={low_count}\n"
        f"Top Vulnerabilities: {', '.join(str(f.get('title', 'Finding')) for f in findings[:5])}\n"
        f"Compliance status details: {str(compliance_report or 'No compliance mappings available')}"
    )


__all__ = [
    "render_user_prompt_explain",
    "render_user_prompt_patch",
    "render_user_prompt_summary",
    "render_user_prompt_triage",
    "truncate_context",
]

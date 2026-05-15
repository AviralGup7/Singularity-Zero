"""Intelligence findings merger and history annotator.

Merges analysis results from multiple plugins into a unified findings list
with severity scoring, deduplication, and priority ranking. Also provides
finding history annotation to track new vs existing findings across runs.

This package modularizes the findings logic into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

# Re-export for backward compatibility
from src.analysis.intelligence.findings_dedup import finding_key as _finding_key_internal

from ._categories import MITRE_ATTACK_MAPPING, SEVERITY_SCORES
from ._history import annotate_finding_history
from ._merge_orchestrator import merge_findings
from ._scoring import confidence_for_evidence, confidence_reasoning


def _finding_key(item: dict[str, Any]) -> str:  # noqa: unused
    return _finding_key_internal(item)


def correlate_validation_findings(
    findings: list[dict[str, Any]], validation_summary: dict[str, Any]
) -> list[dict[str, Any]]:
    """Enrich findings with validation context when available."""
    validation_lookup: dict[tuple[str, str], dict[str, Any]] = {}
    results: dict[str, Any] = (
        validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
    )
    for category, items in results.items():
        if isinstance(items, list):
            for v_item in items:
                if not isinstance(v_item, dict):
                    continue
                url = str(v_item.get("url", "")).strip()
                if url:
                    key = (url, str(category).lower())
                    validation_lookup[key] = v_item

    enriched: list[dict[str, Any]] = []
    for finding in findings:
        url = str(finding.get("url", "")).strip()
        category = str(finding.get("category", "")).lower()
        if not url or not category:
            enriched.append(finding)
            continue

        v_key = (url, category)
        v_result = validation_lookup.get(v_key)

        if v_result:
            evidence = dict(finding.get("evidence", {}) or {})
            evidence["validation_state"] = v_result.get("validation_state", "unknown")
            evidence["validation_evidence"] = {
                k: v
                for k, v in v_result.items()
                if k not in {"url", "module", "category"}
                and isinstance(v, (str, int, float, bool, list, dict, type(None)))
            }

            v_state = str(v_result.get("validation_state", "")).lower()
            current_confidence = float(finding.get("confidence", 0))
            if v_state in {"confirmed", "active_ready", "exploitable"}:
                evidence["validation_confirmed"] = True
                new_confidence = min(current_confidence + 0.15, 0.98)
            elif v_state in {"unconfirmed", "inactive", "false_positive"}:
                evidence["validation_confirmed"] = False
                new_confidence = max(current_confidence - 0.10, 0.20)
            else:
                new_confidence = current_confidence

            enriched.append(
                {**finding, "confidence": round(new_confidence, 2), "evidence": evidence}
            )
        else:
            enriched.append(finding)

    return enriched


def enrich_with_cvss(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:  # noqa: unused
    """Add CVSS v3.1 scores to findings for standardized severity assessment."""
    try:
        from src.analysis.cvss_scoring import enrich_findings_with_cvss

        return enrich_findings_with_cvss(findings)
    except Exception:
        return findings


__all__ = [
    "SEVERITY_SCORES",
    "MITRE_ATTACK_MAPPING",
    "merge_findings",
    "annotate_finding_history",
    "correlate_validation_findings",
    "confidence_for_evidence",
    "confidence_reasoning",
]

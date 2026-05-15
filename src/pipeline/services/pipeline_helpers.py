"""Pipeline helper utilities for the orchestrator.

Contains static helper methods for finding identity computation,
detection coverage analysis, and feedback URL extraction.
Extracted from pipeline_orchestrator.py for better separation of concerns.
"""

from typing import Any
from urllib.parse import urlparse


def finding_identity(finding: dict[str, Any]) -> str:
    """Compute a unique identity string for a finding."""
    return "|".join(
        [
            str(finding.get("category", "")).strip().lower(),
            str(finding.get("url", "")).strip().lower(),
            str(finding.get("title", "")).strip().lower(),
        ]
    )


def compute_detection_coverage(
    analysis_results: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compute detection coverage metrics across all analysis modules.

    Tracks which modules produced findings, coverage by vulnerability category,
    and signal distribution. The module ratio here is a detection yield metric
    (modules with findings / modules evaluated), not an execution-success metric.
    """
    modules_with_findings: list[str] = []
    modules_without_findings: list[str] = []
    category_counts: dict[str, int] = {}
    signal_counts: dict[str, int] = {}

    for module_name, results in analysis_results.items():
        if isinstance(results, list) and len(results) > 0:
            modules_with_findings.append(module_name)
        else:
            modules_without_findings.append(module_name)

    for finding in findings:
        cat = str(finding.get("category", "unknown")).lower()
        category_counts[cat] = category_counts.get(cat, 0) + 1
        evidence = finding.get("evidence", {}) or {}
        for sig in evidence.get("signals", []):
            sig_str = str(sig).lower()
            signal_counts[sig_str] = signal_counts.get(sig_str, 0) + 1

    total_modules = len(modules_with_findings) + len(modules_without_findings)
    detection_yield = round(len(modules_with_findings) / max(total_modules, 1), 2)

    return {
        # Backward-compatible keys used by dashboard/report sections.
        "active_modules": sorted(modules_with_findings),
        "empty_modules": sorted(modules_without_findings),
        # Explicit aliases with clearer semantics.
        "modules_with_findings": sorted(modules_with_findings),
        "modules_without_findings": sorted(modules_without_findings),
        "coverage_by_category": dict(sorted(category_counts.items(), key=lambda x: -x[1])),
        "signal_distribution": dict(sorted(signal_counts.items(), key=lambda x: -x[1])[:20]),
        "coverage_score": detection_yield,
        "detection_yield": detection_yield,
        "total_modules": total_modules,
        "active_count": len(modules_with_findings),
        "empty_count": len(modules_without_findings),
        "modules_with_findings_count": len(modules_with_findings),
        "modules_without_findings_count": len(modules_without_findings),
    }


def build_feedback_targets(
    analysis_results: dict[str, Any],
    limit: int = 40,
) -> list[str]:
    """Extract top URLs from analysis results to feed into nuclei validation.

    Prioritises URLs by finding severity and confidence, returning at most
    *limit* unique URLs for nuclei template scanning.

    Args:
        analysis_results: Per-module analysis results (dict of lists of finding dicts).
        limit: Maximum number of target URLs to return.

    Returns:
        Ordered list of unique URLs for nuclei scanning.
    """
    from urllib.parse import urlparse

    scored: list[tuple[int, str]] = []
    seen: set[str] = set()

    severity_order = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}

    for _module_name, results in analysis_results.items():
        if not isinstance(results, list):
            continue
        for finding in results:
            if not isinstance(finding, dict):
                continue
            url = str(finding.get("url", "")).strip()
            if not url:
                continue
            parsed_check = urlparse(url)
            if not (parsed_check.scheme and parsed_check.netloc):
                continue
            if url in seen:
                continue
            seen.add(url)
            severity = severity_order.get(str(finding.get("severity", "info")).lower(), 0)
            confidence = int(float(finding.get("confidence", 0)) * 100)
            scored.append((severity + confidence, url))

    scored.sort(key=lambda x: -x[0])
    return [url for _, url in scored[:limit]]


def extract_feedback_urls(findings: list[dict[str, Any]], new_keys: set[str]) -> set[str]:
    """Extract feedback URLs from findings, prioritized by severity and confidence.

    Only extracts URLs from NEW findings (those in new_keys) and prioritizes
    high-severity, high-confidence findings for the next iteration.
    """
    url_priorities: list[tuple[int, str]] = []
    resource_groups: dict[str, list[str]] = {}

    for finding in findings:
        if finding_identity(finding) not in new_keys:
            continue

        severity_score = {"critical": 100, "high": 80, "medium": 50, "low": 20}.get(
            str(finding.get("severity", "low")).lower(), 20
        )
        confidence_score = int(float(finding.get("confidence", 0)) * 100)
        decision_bonus = 10 if str(finding.get("decision", "")).upper() == "HIGH" else 0
        mitre_bonus = 5 if finding.get("mitre_attack") else 0
        correlation_bonus = 8 if len(finding.get("source_modules", [])) > 1 else 0
        repro_bonus = (
            6
            if finding.get("evidence", {}).get("reproducible")
            or finding.get("evidence", {}).get("confirmed")
            else 0
        )
        priority = (
            severity_score
            + confidence_score
            + decision_bonus
            + mitre_bonus
            + correlation_bonus
            + repro_bonus
        )

        candidates: list[str] = []
        primary = str(finding.get("url", "")).strip()
        if primary:
            parsed = urlparse(primary)
            if parsed.scheme and parsed.netloc:
                candidates.append(primary)
                path_segments = parsed.path.strip("/").split("/")
                if len(path_segments) >= 2:
                    resource_key = f"{parsed.netloc}/{path_segments[0]}"
                    resource_groups.setdefault(resource_key, []).append(primary)
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        for key in ("mutated_url", "requested_url", "final_url"):
            candidate = str(evidence.get(key, "")).strip()
            if not candidate:
                continue
            parsed = urlparse(candidate)
            if parsed.scheme and parsed.netloc:
                candidates.append(candidate)

        for candidate in candidates:
            url_priorities.append((priority, candidate))

    for resource_key, urls in resource_groups.items():
        if len(urls) >= 1:
            related_urls = set()
            for finding in findings:
                finding_url = str(finding.get("url", "")).strip()
                if finding_url and finding_url not in {u for _, u in url_priorities}:
                    parsed = urlparse(finding_url)
                    finding_resource = (
                        f"{parsed.netloc}/{parsed.path.strip('/').split('/')[0]}"
                        if parsed.path.strip("/")
                        else ""
                    )
                    if finding_resource == resource_key:
                        related_urls.add(finding_url)
            for related_url in related_urls:
                url_priorities.append((priority - 10, related_url))

    url_priorities.sort(key=lambda x: -x[0])
    return {url for _, url in url_priorities}


def build_stage_input_from_context(stage_name: str, config: Any, ctx: Any) -> Any:
    """Build a StageInput contract from context and config."""
    from src.core.contracts.pipeline_runtime import PipelineInput
    from src.pipeline.services.pipeline_orchestrator._constants import STAGE_ORDER

    stage_index = (STAGE_ORDER.index(stage_name) + 1) if stage_name in STAGE_ORDER else 0
    stage_total = len(STAGE_ORDER)
    pipeline_input = PipelineInput(
        target_name=getattr(config, "target_name", "unknown") or "unknown",
        scope_entries=tuple(ctx.scope_entries),
        run_id="runtime",
    )
    runtime_cfg = {
        "mode": str(getattr(config, "mode", "default") or "default"),
        "filters": dict(getattr(config, "filters", {}) or {}),
        "analysis": dict(getattr(config, "analysis", {}) or {}),
        "scoring": dict(getattr(config, "scoring", {}) or {}),
    }
    return ctx.build_stage_input(
        stage_name=stage_name,
        stage_index=stage_index,
        stage_total=stage_total,
        pipeline_input=pipeline_input,
        runtime=runtime_cfg,
    )

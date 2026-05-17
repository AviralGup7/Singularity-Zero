import time
from pathlib import Path
from typing import Any

from src.analysis.behavior.artifacts import write_plugin_artifacts
from src.analysis.helpers import resolve_endpoint_key
from src.analysis.intelligence.endpoint_attack_graph import build_attack_graph
from src.analysis.intelligence.endpoint_graphs import (
    build_auth_context_mapping,
    build_endpoint_relationship_graph,
    build_finding_graph,
    build_shared_parameter_tracking,
)
from src.core.models import DIFF_TARGETS
from src.core.plugins import register_plugin
from src.core.utils import ist_timestamp
from src.pipeline.storage import read_lines, write_json, write_lines
from src.reporting.html import build_dashboard_index as render_dashboard_index
from src.reporting.html import generate_run_report


def _unique_findings(findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    unique = []
    seen: set[str] = set()
    for item in findings:
        endpoint_key = resolve_endpoint_key(item.get("evidence", {}), item.get("url", ""))
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        unique.append(item)
        if len(unique) >= limit:
            break
    return unique


def _top_actionable_targets(
    endpoint_intelligence: list[dict[str, Any]], limit: int = 3
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in endpoint_intelligence:
        labels = item.get("flow_labels") or [f"host:{item.get('host', '')}"]
        flow_key = "|".join(labels)
        entry = grouped.setdefault(
            flow_key,
            {
                "flow": labels,
                "score": 0,
                "decision": item.get("decision", "MEDIUM"),
                "targets": [],
                "signals": set(),
            },
        )
        entry["score"] = max(entry.get("score", 0), int(item.get("score", 0)))
        if item.get("decision") == "HIGH":
            entry["decision"] = "HIGH"
        entry["targets"].append(item.get("url", ""))
        entry["signals"].update(item.get("signals", []))
    top = sorted(
        grouped.values(),
        key=lambda item: (item["decision"] != "HIGH", -item.get("score", 0), len(item["targets"])),
    )[:limit]
    return [
        {
            "flow": item["flow"],
            "score": item.get("score", 0),
            "decision": item["decision"],
            "signals": sorted(item["signals"]),
            "targets": item["targets"][:3],
        }
        for item in top
    ]


def list_run_dirs(target_root: Path) -> list[Path]:
    if not target_root.exists():
        return []
    runs = [
        path
        for path in target_root.iterdir()
        if path.is_dir() and (path / "run_summary.json").exists()
    ]
    return sorted(runs, key=lambda p: (p.stat().st_mtime, str(p)))


def find_previous_run(target_root: Path) -> Path | None:
    runs = list_run_dirs(target_root)
    return runs[-1] if runs else None


def build_artifact_diff(
    previous_run: Path | None, current_values: dict[str, set[str]], run_dir: Path
) -> dict[str, Any] | None:
    if previous_run is None:
        return None

    diff_summary: dict[str, Any] = {"previous_run": str(previous_run), "artifacts": {}}
    for label, filename in DIFF_TARGETS.items():
        previous_items = read_lines(previous_run / filename)
        current_items = current_values.get(label, set())
        added = current_items - previous_items
        removed = previous_items - current_items

        write_lines(run_dir / f"diff_{label}_added.txt", added)
        write_lines(run_dir / f"diff_{label}_removed.txt", removed)
        diff_summary["artifacts"][label] = {
            "previous_count": len(previous_items),
            "current_count": len(current_items),
            "added_count": len(added),
            "removed_count": len(removed),
            "sample_added": sorted(added)[:15],
            "sample_removed": sorted(removed)[:15],
        }
    return diff_summary


EXPORTER = "exporter"


@register_plugin(EXPORTER, "summary")
def build_summary(
    target_name: str,
    scope_entries: list[str],
    subdomains: set[str],
    live_records: list[dict[str, Any]],
    urls: set[str],
    parameters: set[str],
    priority_urls: set[str],
    ranked_priority_urls: list[dict[str, Any]],
    screenshots: list[dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]],
    merged_findings: list[dict[str, Any]],
    tools: dict[str, bool],
    module_metrics: dict[str, dict[str, Any]],
    attack_surface: dict[str, int],
    target_profile: dict[str, int | bool],
    technology_summary: list[dict[str, Any]],
    endpoint_intelligence: list[dict[str, Any]],
    trend_summary: dict[str, Any],
    next_steps: list[str],
    high_confidence_shortlist: list[dict[str, Any]],
    manual_verification_queue: list[dict[str, Any]],
    cross_finding_correlation: list[dict[str, Any]],
    vrt_coverage: dict[str, Any],
    verified_exploits: list[dict[str, Any]],
    validation_summary: dict[str, Any],
    campaign_summary: dict[str, Any],
    review_settings: dict[str, Any],
    validation_settings: dict[str, Any],
    started_at: float,
    previous_run: Path | None,
    pipeline_flow: list[dict[str, object]],
) -> dict[str, Any]:
    counts = {
        "scope_entries": len(scope_entries),
        "subdomains": len(subdomains),
        "live_hosts": len(live_records),
        "urls": len(urls),
        "parameters": len(parameters),
        "priority_urls": len(priority_urls),
        "screenshots": sum(1 for item in screenshots if item.get("file")),
        "attack_campaigns": campaign_summary.get("summary", {}).get("total_campaigns", 0),
    }
    for label, findings in analysis_results.items():
        counts[label] = len(findings)
    validation_results = (
        validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
    )
    counts["validation_results"] = sum(len(items) for items in validation_results.values())
    counts["validated_leads"] = len(verified_exploits)
    coverage_summary = vrt_coverage.get("summary", {}) if isinstance(vrt_coverage, dict) else {}
    counts["vrt_direct"] = int(coverage_summary.get("direct", 0))
    counts["vrt_signal_only"] = int(coverage_summary.get("signal_only", 0))
    counts["vrt_disabled"] = int(coverage_summary.get("disabled", 0))
    counts["vrt_unsupported"] = int(coverage_summary.get("unsupported", 0))

    # Calculate scan quality metrics
    scan_quality = _calculate_scan_quality(
        analysis_results=analysis_results,
        merged_findings=merged_findings,
        module_metrics=module_metrics,
        validation_summary=validation_summary,
        endpoint_intelligence=endpoint_intelligence,
        urls=urls,
        parameters=parameters,
    )

    return {
        "target_name": target_name,
        "generated_at_ist": ist_timestamp(),
        "duration_seconds": round(time.time() - started_at, 2),
        "previous_run": str(previous_run) if previous_run else "",
        "counts": counts,
        "scan_quality": scan_quality,
        "high_value_endpoints": ranked_priority_urls[:20],
        "prioritized_endpoints": endpoint_intelligence[:20],
        "attack_graph": build_attack_graph(
            endpoint_intelligence,
            analysis_results,
            node_limit=max(20, int(review_settings.get("attack_graph_node_limit", 220))),
            edge_limit=max(20, int(review_settings.get("attack_graph_edge_limit", 320))),
            chain_limit=max(1, int(review_settings.get("attack_graph_chain_limit", 14))),
            max_chain_depth=max(2, int(review_settings.get("attack_graph_max_depth", 4))),
        ),
        "endpoint_relationship_graph": build_endpoint_relationship_graph(endpoint_intelligence),
        "shared_parameter_tracking": build_shared_parameter_tracking(endpoint_intelligence),
        "auth_context_mapping": build_auth_context_mapping(endpoint_intelligence),
        "finding_graph": build_finding_graph(endpoint_intelligence, analysis_results),
        "top_actionable_findings": _unique_findings(
            merged_findings, int(review_settings.get("top_findings_limit", 5))
        ),
        "top_actionable_targets": _top_actionable_targets(endpoint_intelligence, 3),
        "target_profile": target_profile,
        "technology_summary": technology_summary,
        "attack_surface": attack_surface,
        "trend_summary": trend_summary,
        "next_steps": next_steps,
        "high_confidence_shortlist": high_confidence_shortlist,
        "manual_verification_queue": manual_verification_queue,
        "cross_finding_correlation": cross_finding_correlation,
        "vrt_coverage": vrt_coverage,
        "verified_exploits": verified_exploits[
            : int(review_settings.get("verified_exploit_limit", 5))
        ],
        "validation_results": validation_results,
        "campaign_summary": campaign_summary,
        "validation_meta": {
            "callback_context": validation_summary.get("callback_context", {})
            if isinstance(validation_summary, dict)
            else {},
            "token_replay": validation_summary.get("token_replay", {})
            if isinstance(validation_summary, dict)
            else {},
        },
        "review_settings": review_settings,
        "validation_settings": validation_settings,
        "module_metrics": module_metrics,
        "detection_coverage": module_metrics.get("analysis", {}).get("detection_coverage", {}),
        "pipeline_flow": pipeline_flow,
        "tool_availability": tools,
    }


def _calculate_scan_quality(
    analysis_results: dict[str, list[dict[str, Any]]],
    merged_findings: list[dict[str, Any]],
    module_metrics: dict[str, dict[str, Any]],
    validation_summary: dict[str, Any],
    endpoint_intelligence: list[dict[str, Any]],
    urls: set[str],
    parameters: set[str],
) -> dict[str, object]:
    """Calculate scan quality metrics for the security assessment.

    Provides visibility into how thorough the scan was and identifies
    areas where coverage could be improved.

    Args:
        analysis_results: Dict of module_name -> list of results.
        merged_findings: List of merged findings.
        module_metrics: Pipeline module metrics.
        validation_summary: Validation results summary.
        endpoint_intelligence: Endpoint intelligence data.
        urls: Set of URLs discovered.
        parameters: Set of parameters discovered.

    Returns:
        Dict with scan quality metrics and recommendations.
    """
    # Count modules that produced findings (signal yield), not raw execution count.
    modules_with_findings = len([k for k in analysis_results if analysis_results[k]])
    total_modules = len(analysis_results)
    module_signal_yield = (
        round(modules_with_findings / max(total_modules, 1) * 100, 1) if total_modules > 0 else 0
    )

    # Count validation coverage
    validation_results = (
        validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
    )
    validated_count = sum(len(items) for items in validation_results.values())
    validation_coverage = (
        round(validated_count / max(len(merged_findings), 1) * 100, 1) if merged_findings else 0
    )

    # Count high-confidence findings
    high_confidence = sum(1 for f in merged_findings if float(f.get("confidence", 0)) >= 0.7)
    high_confidence_pct = (
        round(high_confidence / max(len(merged_findings), 1) * 100, 1) if merged_findings else 0
    )

    # Count endpoints with intelligence data
    intelligence_coverage = (
        round(len(endpoint_intelligence) / max(len(urls), 1) * 100, 1) if urls else 0
    )

    # Calculate iteration quality (if available)
    raw_iteration_details: Any = module_metrics.get("iteration_details", [])
    iteration_details: list[dict[str, Any]] = (
        raw_iteration_details if isinstance(raw_iteration_details, list) else []
    )
    avg_iterations = len(iteration_details)
    avg_iteration_duration = (
        round(
            sum(d.get("duration_seconds", 0) for d in iteration_details) / max(avg_iterations, 1), 2
        )
        if iteration_details
        else 0
    )

    # Overall quality score (0-100)
    quality_score = round(
        (
            module_signal_yield * 0.3
            + validation_coverage * 0.3
            + high_confidence_pct * 0.2
            + intelligence_coverage * 0.2
        ),
        1,
    )

    # Generate recommendations
    recommendations: list[str] = []
    if module_signal_yield < 10:
        recommendations.append(
            f"Only {module_signal_yield}% of modules produced findings — widen scope or use deeper active validation to increase signal."
        )
    if validation_coverage < 50:
        recommendations.append(
            f"Validation coverage is {validation_coverage}% — enable active validation for confirmed findings."
        )
    if high_confidence_pct < 30:
        recommendations.append(
            f"Only {high_confidence_pct}% high-confidence findings — consider deeper analysis modes."
        )
    if intelligence_coverage < 60:
        recommendations.append(
            f"Endpoint intelligence coverage is {intelligence_coverage}% — more URLs need analysis."
        )
    if not recommendations:
        recommendations.append("Scan quality is good across all metrics.")

    return {
        "overall_quality_score": min(quality_score, 100),
        # Backward-compatible key retained for downstream consumers.
        "module_coverage_pct": module_signal_yield,
        "module_signal_yield_pct": module_signal_yield,
        "validation_coverage_pct": validation_coverage,
        "high_confidence_pct": high_confidence_pct,
        "intelligence_coverage_pct": intelligence_coverage,
        # Backward-compatible key retained for downstream consumers.
        "total_modules_ran": modules_with_findings,
        "total_modules_with_findings": modules_with_findings,
        "total_modules_available": total_modules,
        "validated_findings": validated_count,
        "total_findings": len(merged_findings),
        "high_confidence_findings": high_confidence,
        "iteration_count": avg_iterations,
        "avg_iteration_duration_seconds": avg_iteration_duration,
        "recommendations": recommendations,
    }


def build_dashboard_index(target_root: Path) -> None:
    render_dashboard_index(target_root, list_run_dirs(target_root))


def persist_run_outputs(
    run_dir: Path,
    summary: dict[str, Any],
    diff_summary: dict[str, Any] | None,
    screenshots: list[dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]],
    merged_findings: list[dict[str, Any]],
) -> None:
    if diff_summary:
        write_json(run_dir / "diff_summary.json", diff_summary)
    if screenshots:
        write_json(run_dir / "screenshots.json", screenshots)
    write_plugin_artifacts(run_dir, analysis_results)
    write_json(run_dir / "findings.json", merged_findings)
    write_json(run_dir / "verified_exploits.json", summary.get("verified_exploits", []))
    write_json(run_dir / "validation_results.json", summary.get("validation_results", {}))
    write_json(run_dir / "custom_validation_results.json", summary.get("validation_results", {}))
    write_json(run_dir / "run_summary.json", summary)


__all__ = [
    "build_artifact_diff",
    "build_dashboard_index",
    "build_summary",
    "find_previous_run",
    "generate_run_report",
    "list_run_dirs",
    "persist_run_outputs",
]

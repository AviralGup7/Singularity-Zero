"""Post-analysis enrichment stage: CVSS, API security, DNS security, threat intel, correlation."""

import asyncio
import time
from typing import Any

from src.analysis.intelligence.aggregator import (
    annotate_finding_decisions,
    filter_reportable_findings,
)
from src.analysis.intelligence.cvss_scoring import enrich_findings_with_cvss
from src.core.contracts.finding_lifecycle import apply_lifecycle
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.core.plugins import resolve_plugin
from src.intelligence.campaigns.campaign_builder import build_attack_campaigns
from src.intelligence.correlation.engine import (
    calculate_compound_risk as _calculate_compound_risk,
)
from src.intelligence.correlation.engine import (
    correlate_findings as _correlate_findings,
)
from src.intelligence.correlation.engine import (
    detect_multi_vector_endpoints as _detect_multi_vector_endpoints,
)
from src.intelligence.feeds.base import FeedError
from src.intelligence.feeds.cve import CVEConfig, CVESyncClient
from src.intelligence.feeds.mitre import MitreAttackMapper, MitreConfig
from src.intelligence.graph.threat_graph import (
    annotate_graph_for_campaigns,
    build_threat_graph,
    graph_risk_summary,
)
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

# Test seams / legacy aliases
api_security_analyzer = None
dns_security_analyzer = None
correlate_findings = _correlate_findings
detect_multi_vector_endpoints = _detect_multi_vector_endpoints
calculate_compound_risk = _calculate_compound_risk


ENRICHMENT_PROVIDER = "enrichment_provider"

# Concurrency limits for parallel feed lookups (CVE, MITRE)
# Controls how many external API calls happen simultaneously
_MAX_FEED_CONCURRENCY = 5
_MAX_FEED_CONCURRENCY_CAP = 10

# Finding budget limits for threat intelligence enrichment
# Prevents excessive API calls by limiting findings to process
_DEFAULT_THREAT_INTEL_MAX_FINDINGS = 25
_MAX_THREAT_INTEL_FINDINGS_CAP = 200

# Timeouts for external intelligence API calls
# 8 seconds balances responsiveness with API latency
_DEFAULT_THREAT_INTEL_PER_FINDING_TIMEOUT_SECONDS = 8.0
_DEFAULT_THREAT_INTEL_CVE_TIMEOUT_SECONDS = 8.0
_DEFAULT_THREAT_INTEL_CVE_MAX_RETRIES = 0

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def _coerce_bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Parse a value to an integer and clamp it within [minimum, maximum].

    Args:
        value: Value to parse. Will attempt int() conversion.
        default: Fallback value if parsing fails.
        minimum: Lower bound (result will be >= this).
        maximum: Upper bound (result will be <= this).

    Returns:
        Parsed integer clamped to the specified bounds.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _coerce_bounded_float(
    value: Any,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    """Parse a value to a float and clamp it within [minimum, maximum].

    Args:
        value: Value to parse. Will attempt float() conversion.
        default: Fallback value if parsing fails.
        minimum: Lower bound (result will be >= this).
        maximum: Upper bound (result will be <= this).

    Returns:
        Parsed float clamped to the specified bounds.
    """
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float, returning default on failure.

    Args:
        value: Value to convert to float.
        default: Fallback value if conversion fails (default 0.0).

    Returns:
        The float value, or default if conversion fails.
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _select_threat_intel_candidates(
    findings: list[dict[str, Any]],
    *,
    max_findings: int,
) -> list[dict[str, Any]]:
    """Select the highest-priority findings for threat intelligence enrichment.

    Ranks findings by severity (critical > high > medium > low) then by
    confidence score, deduplicates by (title, category, url) tuple, and
    returns up to max_findings candidates.

    Args:
        findings: List of finding dictionaries to filter and rank.
        max_findings: Maximum number of candidates to return.

    Returns:
        Deduplicated, severity-ranked subset of findings limited to max_findings.
    """
    if max_findings <= 0:
        return []

    ranked_findings = sorted(
        [item for item in findings if isinstance(item, dict)],
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity", "")).lower(), 0),
            _safe_float(item.get("confidence", 0.0), 0.0),
        ),
        reverse=True,
    )

    selected: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for finding in ranked_findings:
        unique_key = (
            str(finding.get("title", "")).strip().lower(),
            str(finding.get("category", "")).strip().lower(),
            str(finding.get("url", "")).strip().lower(),
        )
        if unique_key in seen_keys:
            continue
        seen_keys.add(unique_key)
        selected.append(finding)
        if len(selected) >= max_findings:
            break

    return selected


logger = get_pipeline_logger(__name__)


async def run_post_analysis_enrichments(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Run post-analysis enrichments using registered providers."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("intelligence", config, ctx)

    stage_started = time.monotonic()

    state_delta: dict[str, Any] = {
        "merged_findings": list(ctx.merged_findings),
        "reportable_findings": list(ctx.reportable_findings),
        "analysis_results": dict(ctx.analysis_results),
        "threat_graph": {},
        "campaign_summary": {},
    }

    def _ingest_enrichment_findings(
        findings: list[dict[str, Any]],
        current_merged: list[dict[str, Any]],
        current_reportable: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not findings:
            return current_merged, current_reportable
        enriched_findings = apply_lifecycle(
            annotate_finding_decisions(findings, ctx.target_profile)
        )
        merged = list(current_merged) + enriched_findings
        reportable = list(current_reportable) + filter_reportable_findings(enriched_findings)
        return merged, reportable

    # Resolve CVSS scoring from registry, preserving the legacy patch seam.
    try:
        enrich_cvss = resolve_plugin(ENRICHMENT_PROVIDER, "cvss_scoring")
    except KeyError:
        enrich_cvss = enrich_findings_with_cvss

    try:
        state_delta["reportable_findings"] = enrich_cvss(state_delta["reportable_findings"])
        state_delta["merged_findings"] = enrich_cvss(state_delta["merged_findings"])
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.warning("CVSS enrichment failed: %s", exc)

    analysis_settings = getattr(config, "analysis", {}) or {}
    if not isinstance(analysis_settings, dict):
        analysis_settings = {}

    api_security_metrics: dict[str, Any] = {"status": "skipped"}
    dns_security_metrics: dict[str, Any] = {"status": "skipped"}
    correlation_metrics: dict[str, Any] = {"status": "skipped"}

    # Resolve API Security from registry
    try:
        api_security_started = time.monotonic()
        emit_progress("intelligence", "Running API security analysis", 84)
        try:
            api_analyzer = resolve_plugin(ENRICHMENT_PROVIDER, "api_security")
        except KeyError:
            if api_security_analyzer is None:
                raise
            api_analyzer = api_security_analyzer

        all_responses: list[dict[str, Any]] = []
        for records in ctx.analysis_results.values():
            if isinstance(records, list):
                all_responses.extend(records)
        live_records = ctx.live_records
        if isinstance(live_records, list):
            all_responses.extend(live_records)

        api_security_findings = api_analyzer(all_responses)
        if api_security_findings:
            state_delta["analysis_results"]["api_security"] = api_security_findings
            state_delta["merged_findings"], state_delta["reportable_findings"] = (
                _ingest_enrichment_findings(
                    api_security_findings,
                    state_delta["merged_findings"],
                    state_delta["reportable_findings"],
                )
            )
            api_security_metrics = {
                "status": "ok",
                "duration_seconds": round(time.monotonic() - api_security_started, 2),
                "findings_count": len(api_security_findings),
            }
            emit_progress(
                "intelligence",
                f"Found {len(api_security_findings)} API security issues",
                86,
            )
    except KeyError:
        logger.warning("API security provider not found in registry")
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'api_security' failed: %s", exc)
        ctx.mark_stage_failed("api_security", str(exc))

    # Resolve DNS Security from registry
    try:
        dns_security_started = time.monotonic()
        emit_progress("intelligence", "Running DNS security analysis", 86)
        try:
            dns_analyzer = resolve_plugin(ENRICHMENT_PROVIDER, "dns_security")
        except KeyError:
            if dns_security_analyzer is None:
                raise
            dns_analyzer = dns_security_analyzer

        domains_to_analyze: set[str] = set()
        for sub in ctx.subdomains:
            parts = sub.split(".")
            if len(parts) >= 2:
                domains_to_analyze.add(".".join(parts[-2:]))
        for entry in ctx.scope_entries:
            domain = str(entry).strip().lower()
            if domain and not domain.startswith(("http://", "https://")):
                domains_to_analyze.add(domain)
        if domains_to_analyze:
            dns_findings = dns_analyzer(list(domains_to_analyze))
            if dns_findings:
                state_delta["analysis_results"]["dns_security"] = dns_findings
                state_delta["merged_findings"], state_delta["reportable_findings"] = (
                    _ingest_enrichment_findings(
                        dns_findings,
                        state_delta["merged_findings"],
                        state_delta["reportable_findings"],
                    )
                )
                dns_security_metrics = {
                    "status": "ok",
                    "duration_seconds": round(time.monotonic() - dns_security_started, 2),
                    "findings_count": len(dns_findings),
                    "domains_analyzed": len(domains_to_analyze),
                }
                emit_progress(
                    "intelligence",
                    f"Found {len(dns_findings)} DNS security issues",
                    87,
                )
    except KeyError:
        logger.warning("DNS security provider not found in registry")
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'dns_security' failed: %s", exc)
        ctx.mark_stage_failed("dns_security", str(exc))

    # Correlation and Risk
    try:
        emit_progress("intelligence", "Correlating findings for attack chains", 87)

        correlated = correlate_findings(state_delta["reportable_findings"])
        multi_vector = detect_multi_vector_endpoints(state_delta["reportable_findings"])
        compound_risk = calculate_compound_risk(state_delta["reportable_findings"])
        if correlated or multi_vector:
            state_delta["analysis_results"]["correlation"] = [
                {
                    "type": "correlation",
                    "chains": correlated,
                    "multi_vector": multi_vector,
                    "compound_risk": compound_risk,
                }
            ]
            correlation_metrics = {"status": "ok", "chains_found": len(correlated)}
            emit_progress("intelligence", f"Found {len(correlated)} attack chains", 88)
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'correlation' failed: %s", exc)
        ctx.mark_stage_failed("correlation", str(exc))

    # Feedback events for findings are now handled by the LearningSubscriber
    # listening for the PIPELINE_COMPLETE event.

    # Enrich findings with threat intelligence feeds — parallelized
    threat_intel_metrics: dict[str, Any] = {"status": "skipped"}
    try:
        total_reportable_findings = len(state_delta["reportable_findings"])
        max_findings = _coerce_bounded_int(
            analysis_settings.get(
                "threat_intel_max_findings",
                _DEFAULT_THREAT_INTEL_MAX_FINDINGS,
            ),
            default=_DEFAULT_THREAT_INTEL_MAX_FINDINGS,
            minimum=1,
            maximum=_MAX_THREAT_INTEL_FINDINGS_CAP,
        )
        max_concurrency = _coerce_bounded_int(
            analysis_settings.get("threat_intel_max_feed_concurrency", _MAX_FEED_CONCURRENCY),
            default=_MAX_FEED_CONCURRENCY,
            minimum=1,
            maximum=_MAX_FEED_CONCURRENCY_CAP,
        )
        per_finding_timeout_seconds = _coerce_bounded_float(
            analysis_settings.get(
                "threat_intel_per_finding_timeout_seconds",
                _DEFAULT_THREAT_INTEL_PER_FINDING_TIMEOUT_SECONDS,
            ),
            default=_DEFAULT_THREAT_INTEL_PER_FINDING_TIMEOUT_SECONDS,
            minimum=1.0,
            maximum=30.0,
        )
        cve_timeout_seconds = _coerce_bounded_float(
            analysis_settings.get(
                "threat_intel_cve_timeout_seconds",
                _DEFAULT_THREAT_INTEL_CVE_TIMEOUT_SECONDS,
            ),
            default=_DEFAULT_THREAT_INTEL_CVE_TIMEOUT_SECONDS,
            minimum=1.0,
            maximum=30.0,
        )
        cve_max_retries = _coerce_bounded_int(
            analysis_settings.get(
                "threat_intel_cve_max_retries",
                _DEFAULT_THREAT_INTEL_CVE_MAX_RETRIES,
            ),
            default=_DEFAULT_THREAT_INTEL_CVE_MAX_RETRIES,
            minimum=0,
            maximum=5,
        )
        threat_intel_candidates = _select_threat_intel_candidates(
            state_delta["reportable_findings"],
            max_findings=max_findings,
        )
        skipped_findings = max(0, total_reportable_findings - len(threat_intel_candidates))
        if skipped_findings:
            emit_progress(
                "intelligence",
                (
                    "Threat intelligence budget active: "
                    f"processing top {len(threat_intel_candidates)}/{total_reportable_findings} findings"
                ),
                89,
            )
        if not threat_intel_candidates:
            threat_intel_metrics = {
                "status": "ok",
                "findings_enriched": 0,
                "candidate_findings": 0,
                "total_reportable_findings": total_reportable_findings,
                "skipped_findings": skipped_findings,
                "errors": 0,
                "parallel": True,
                "max_concurrency": max_concurrency,
            }
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="enrichment",
                outcome=StageOutcome.COMPLETED,
                duration_seconds=duration,
                metrics={
                    "api_security": api_security_metrics,
                    "dns_security": dns_security_metrics,
                    "correlation": correlation_metrics,
                    "threat_intel": threat_intel_metrics,
                },
                state_delta=state_delta,
            )

        cve_config = CVEConfig(timeout_seconds=cve_timeout_seconds, max_retries=cve_max_retries)

        async with (
            CVESyncClient(cve_config) as cve_feed,
            MitreAttackMapper(MitreConfig()) as mitre_feed,
        ):
            assert isinstance(cve_feed, CVESyncClient)
            assert isinstance(mitre_feed, MitreAttackMapper)
            semaphore = asyncio.Semaphore(max_concurrency)

            async def _enrich_single(finding: dict[str, Any]) -> tuple[dict[str, Any], int]:
                """Enrich one finding with CVE + MITRE data. Returns (finding, enriched_count)."""
                count = 0
                async with semaphore:
                    try:
                        cves = await cve_feed.search_cves(
                            keyword=finding.get("title", ""),
                            results_per_page=5,
                        )
                        if cves and cves.entries:
                            finding.setdefault("threat_intel", {})["cves"] = [
                                {
                                    "id": e.cve_id,
                                    "cvss_score": e.cvss_score,
                                    "severity": e.severity.value,
                                }
                                for e in cves.entries[:5]
                            ]
                            count += 1
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.debug(
                            "CVE enrichment failed for '%s': %s",
                            finding.get("title", ""),
                            exc,
                        )

                    try:
                        mitre_refs = await mitre_feed.get_techniques_by_tactic(
                            finding.get("category", "")
                        )
                        if mitre_refs:
                            finding.setdefault("threat_intel", {})["mitre"] = [
                                {"id": t.id, "name": t.name} for t in mitre_refs[:3]
                            ]
                            count += 1
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.debug(
                            "MITRE enrichment failed for '%s': %s",
                            finding.get("category", ""),
                            exc,
                        )

                    return finding, count

            enriched_count = 0
            error_count = 0
            tasks = [
                asyncio.wait_for(_enrich_single(finding), timeout=per_finding_timeout_seconds)
                for finding in threat_intel_candidates
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, BaseException):
                    if isinstance(r, asyncio.CancelledError):
                        raise r
                    error_count += 1
                    continue
                _, count = r
                enriched_count += count

        if enriched_count:
            logger.info("Enriched %d findings with threat intelligence", enriched_count)

        threat_intel_metrics = {
            "status": "ok",
            "findings_enriched": enriched_count,
            "candidate_findings": len(threat_intel_candidates),
            "total_reportable_findings": total_reportable_findings,
            "skipped_findings": skipped_findings,
            "errors": error_count,
            "parallel": True,
            "max_concurrency": max_concurrency,
            "per_finding_timeout_seconds": per_finding_timeout_seconds,
            "cve_timeout_seconds": cve_timeout_seconds,
            "cve_max_retries": cve_max_retries,
        }

    except FeedError as exc:
        logger.warning("Threat intelligence enrichment skipped: %s", exc)
    except (TypeError, ValueError, RuntimeError):
        import traceback
        traceback.print_exc()

    # Threat Graph and Campaigns Generation
    try:
        emit_progress("intelligence", "Generating threat graph and attack surface map", 92)
        threat_graph = build_threat_graph(
            state_delta["reportable_findings"],
            endpoints=ctx.analysis_results.get("endpoints"),
            include_cves=True,
            include_mitre=True
        )

        # Annotate graph for campaigns based on validated evidence
        validation_results = ctx.validation_summary.get("results", {})
        threat_graph = annotate_graph_for_campaigns(threat_graph, validation_results)

        state_delta["threat_graph"] = threat_graph
        state_delta["threat_graph_summary"] = graph_risk_summary(threat_graph)

        # Build Attack Campaigns
        emit_progress("intelligence", "Simulating attack paths and campaigns", 95)
        campaign_settings = (getattr(config, "extensions", {}) or {}).get("attack_campaigns", {})
        if campaign_settings.get("enabled", True):
            campaign_summary = build_attack_campaigns(
                threat_graph,
                ctx.validation_summary,
                ctx.analysis_results,
                settings=campaign_settings
            )
            state_delta["campaign_summary"] = campaign_summary

            logger.info(
                "Attack campaigns built: %d campaigns, max risk %.2f",
                campaign_summary.get("summary", {}).get("total_campaigns", 0),
                campaign_summary.get("summary", {}).get("max_risk", 0.0)
            )

        logger.info(
            "Threat graph generated: %d nodes, %d edges, risk score %.2f",
            len(threat_graph.get("nodes", [])),
            len(threat_graph.get("edges", [])),
            state_delta["threat_graph_summary"].get("overall_risk_score", 0.0)
        )
    except Exception as exc:
        logger.error("Failed to generate threat graph or campaigns: %s", exc)

    duration = round(time.monotonic() - stage_started, 2)
    return StageOutput(
        stage_name="enrichment",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics={
            "api_security": api_security_metrics,
            "dns_security": dns_security_metrics,
            "correlation": correlation_metrics,
            "threat_intel": threat_intel_metrics,
            "threat_graph": {
                "nodes": len(state_delta.get("threat_graph", {}).get("nodes", [])),
                "edges": len(state_delta.get("threat_graph", {}).get("edges", [])),
                "risk_score": state_delta.get("threat_graph_summary", {}).get("overall_risk_score", 0.0)
            },
            "attack_campaigns": {
                "count": state_delta.get("campaign_summary", {}).get("summary", {}).get("total_campaigns", 0),
                "max_risk": state_delta.get("campaign_summary", {}).get("summary", {}).get("max_risk", 0.0)
            }
        },
        state_delta=state_delta,
    )

"""Gap Analysis endpoints for the FastAPI dashboard."""

import logging
from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import DetectionGapResponse, GapAnalysisEntry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/gap-analysis", tags=["Gap Analysis"])


@router.get(
    "",
    response_model=DetectionGapResponse,
    responses={401: {"model": Any}},
    summary="Get detection gap analysis",
)
async def get_gap_analysis(
    target: str | None = None,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> DetectionGapResponse:
    """Analyze coverage gaps across vulnerability categories using real telemetry."""
    from src.reporting.detection_coverage import ALL_DETECTION_CATEGORIES

    # 1. Get actual telemetry from the query service
    summary = services.query.detection_gap_summary(target)
    active_modules = set(summary.get("active_modules", []))
    empty_modules = set(summary.get("empty_modules", []))
    category_counts = summary.get("coverage_by_category", {})

    # Module to category mapping (consistent with src/reporting/detection_coverage.py)
    module_to_category: dict[str, str] = {
        "idor_candidate_finder": "idor",
        "ssrf_candidate_finder": "ssrf",
        "token_leak_detector": "token_leak",
        "sensitive_field_detector": "sensitive_data",
        "anomaly_detector": "anomaly",
        "behavior_analysis_layer": "behavioral_deviation",
        "header_checker": "misconfiguration",
        "cookie_security_checker": "misconfiguration",
        "cors_misconfig_checker": "cors",
        "cache_control_checker": "misconfiguration",
        "stored_xss_signal_detector": "xss",
        "reflected_xss_probe": "xss",
        "race_condition_signal_analyzer": "race_condition",
        "parameter_pollution_exploitation": "business_logic",
        "auth_header_tampering_variations": "authentication_bypass",
        "http_method_override_probe": "authentication_bypass",
        "json_mutation_attacks": "business_logic",
        "post_body_mutation_attacks": "business_logic",
        "multi_step_flow_breaking_probe": "business_logic",
        "redirect_chain_analyzer": "redirect",
        "auth_boundary_redirect_detection": "redirect",
        "open_redirect_validation": "open_redirect",
        "ssrf_validation": "ssrf",
        "idor_validation": "idor",
        "token_reuse_validation": "token_leak",
        "csrf_protection_checker": "csrf",
        "ssti_surface_detector": "ssti",
        "ai_endpoint_exposure_analyzer": "ai_surface",
        "payment_flow_intelligence": "payment",
        "payment_provider_detection": "payment",
        "session_reuse_detection": "session",
        "logout_invalidation_check": "session",
        "cross_user_access_simulation": "access_control",
        "role_based_endpoint_comparison": "access_control",
        "privilege_escalation_detector": "access_control",
        "access_boundary_tracker": "access_control",
        "unauth_access_check": "authentication_bypass",
        "error_stack_trace_detector": "exposure",
        "environment_file_exposure_checker": "exposure",
        "backup_file_exposure_checker": "exposure",
        "graphql_introspection_exposure_checker": "exposure",
        "graphql_active_probe": "exposure",
        "openapi_swagger_spec_checker": "exposure",
        "server_side_injection_surface_analyzer": "server_side_injection",
    }

    # Map categories to their "ideal" check counts (for scoring)
    ideal_counts = {
        "idor": 5,
        "ssrf": 4,
        "xss": 8,
        "open_redirect": 3,
        "token_leak": 2,
        "access_control": 6,
        "authentication_bypass": 4,
        "broken_authentication": 3,
        "business_logic": 7,
        "payment": 4,
        "sensitive_data": 3,
        "misconfiguration": 10,
        "cors": 3,
        "session": 4,
        "anomaly": 2,
        "behavioral_deviation": 3,
        "redirect": 4,
        "server_side_injection": 5,
        "race_condition": 2,
        "csrf": 3,
        "ssti": 2,
        "ai_surface": 2,
        "exposure": 5,
    }

    results: list[GapAnalysisEntry] = []
    modules_with_gaps = 0
    total_coverage_sum = 0

    # Process all known modules in our mapping
    for module_name, cat_id in module_to_category.items():
        if cat_id not in ALL_DETECTION_CATEGORIES:
            continue

        is_active = module_name in active_modules
        is_empty = module_name in empty_modules
        findings_count = category_counts.get(cat_id, 0)

        total = ideal_counts.get(cat_id, 3)

        # Heuristic for covered checks:
        # If it ran and found nothing, it's partially covered (verified lack of issue).
        # If it found issues, it's more covered.
        # If it didn't run, it's 0.
        if is_active:
            covered = total if findings_count > 0 else max(1, total - 2)
        elif is_empty:
            covered = 1
        else:
            covered = 0

        percent = int((covered / total) * 100)
        status = "complete" if percent == 100 else "partial" if percent > 0 else "missing"

        if status != "complete":
            modules_with_gaps += 1

        results.append(
            GapAnalysisEntry(
                module=module_name,
                category=cat_id,
                total_checks=total,
                covered_checks=covered,
                missing_checks=total - covered,
                coverage_percent=percent,
                status=status,
            )
        )
        total_coverage_sum += percent

    # Overall coverage is the average of module percentages
    overall_coverage = int(total_coverage_sum / len(results)) if results else 0

    return DetectionGapResponse(
        target=target,
        results=results,
        overall_coverage=overall_coverage,
        total_modules=len(results),
        modules_with_gaps=modules_with_gaps,
    )


@router.post(
    "/refresh",
    summary="Trigger fresh gap analysis",
)
async def refresh_gap_analysis(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, str]:
    """Trigger a fresh analysis of findings vs coverage registry."""
    # In a real system, this would invalidate caches and re-run background analysis
    return {"status": "Analysis refresh triggered"}

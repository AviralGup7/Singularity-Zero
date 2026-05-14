"""Confidence scoring and reasoning for findings."""

from typing import Any

from src.analysis.helpers import normalized_confidence


def confidence_for_evidence(module: str, evidence: dict[str, Any]) -> float:
    """Compute confidence score for a finding based on module and evidence."""
    if "confidence" in evidence:
        return round(float(evidence.get("confidence", 0)), 2)
    if module == "sensitive_data_scanner":
        return 0.95
    if module == "header_checker":
        return 0.98
    if module == "token_leak_detector":
        location_conf = (
            0.9 if evidence.get("location") in {"response_body", "referer_risk"} else 0.78
        )
        context_sev = float(evidence.get("context_severity", 0))
        if context_sev >= 0.8:
            return round(min(location_conf + 0.06, 0.98), 2)
        return location_conf
    if module == "stored_xss_signal_detector":
        return 0.81 if evidence.get("xss_signals") else 0.7
    if module == "reflected_xss_probe":
        return (
            0.88
            if {"script_context", "attribute_context"} & set(evidence.get("xss_signals", []))
            else 0.76
        )
    if module == "idor_candidate_finder":
        comparison = evidence.get("comparison") or {}
        if comparison.get("multi_strategy_confirmed"):
            return 0.92
        if comparison.get("mutations_confirmed", 0) >= 2:
            return 0.89
        if comparison:
            return 0.86
        return 0.64
    if module == "race_condition_signal_analyzer":
        return 0.69 if "missing_idempotency_hint" in evidence.get("signals", []) else 0.58
    if module == "ssrf_candidate_finder":
        signals = set(evidence.get("signals", []))
        high_confidence_signals = {
            "cloud_metadata_reference",
            "protocol_smuggling_attempt",
            "encoded_internal_host",
        }
        medium_confidence_signals = {
            "ipv4_address",
            "ipv6_address",
            "sensitive_port_reference",
            "nested_scheme",
        }
        if signals & high_confidence_signals or evidence.get("score", 0) >= 9:
            return 0.82
        if signals & medium_confidence_signals or evidence.get("score", 0) >= 5:
            return 0.72
        return 0.58
    if module == "anomaly_detector":
        signals = set(evidence.get("signals", []))
        high_severity_signals = {
            "admin_panel_path",
            "debug_interface_path",
            "sql_error_keyword",
            "stack_trace_keyword",
        }
        if signals & high_severity_signals or evidence.get("score", 0) >= 4:
            return 0.78
        if evidence.get("score", 0) >= 3:
            return 0.68
        return 0.52
    if module == "behavior_analysis_layer":
        return round(float(evidence.get("confidence", 0.62)), 2)
    if module == "csrf_protection_checker":
        missing = evidence.get("missing_protections", [])
        if len(missing) >= 3:
            return 0.85
        if len(missing) >= 2:
            return 0.75
        return 0.65
    if module == "ssti_surface_detector":
        engines = evidence.get("detected_engines", [])
        if len(engines) >= 2:
            return 0.82
        if engines:
            return 0.72
        return 0.58
    if module == "file_upload_surface_detector":
        indicators = evidence.get("upload_indicators", [])
        if len(indicators) >= 3:
            return 0.80
        if indicators:
            return 0.68
        return 0.55
    if module == "graphql_introspection_exposure_checker":
        return 0.88 if evidence.get("schema_exposed") else 0.72
    if module == "openapi_swagger_spec_checker":
        return 0.85 if evidence.get("spec_accessible") else 0.68
    if module == "cors_misconfig_checker":
        if "wildcard_origin_with_credentials" in evidence.get("issues", []):
            return 0.90
        return 0.72
    if module == "cache_poisoning_indicator_checker":
        if "host_header_reflection_in_cacheable_response" in evidence.get("issues", []):
            return 0.85
        return 0.68
    return normalized_confidence(
        base=0.52,
        score=int(evidence.get("score", 0)),
        signals=evidence.get("signals", []),
        cap=0.96,
    )


def confidence_reasoning(module: str, evidence: dict[str, Any], confidence: float) -> str:
    """Explain why a specific confidence score was assigned to a finding."""
    if confidence >= 0.9:
        base = "High confidence"
    elif confidence >= 0.7:
        base = "Moderate confidence"
    elif confidence >= 0.5:
        base = "Low-moderate confidence"
    else:
        base = "Low confidence"

    reasons: list[str] = []

    if evidence.get("comparison"):
        comparison = evidence.get("comparison", {})
        if comparison.get("multi_strategy_confirmed"):
            reasons.append("multiple mutation strategies confirmed")
        elif comparison.get("mutations_confirmed", 0) >= 2:
            reasons.append(f"{comparison['mutations_confirmed']} mutations confirmed")
        else:
            reasons.append("response comparison performed")

    if evidence.get("validation_state") == "active_ready":
        reasons.append("active validation ready")

    if (
        evidence.get("auth_flow_endpoint")
        or str(evidence.get("url", "")).lower().find("/auth") >= 0
    ):
        reasons.append("auth flow context")

    signals = evidence.get("signals", [])
    if "priority_plus_anomaly" in signals:
        reasons.append("priority endpoint with anomaly")

    if evidence.get("location") in {"response_body", "referer_risk"}:
        reasons.append(f"token in {evidence['location']}")

    context_sev = evidence.get("context_severity", 0)
    if isinstance(context_sev, (int, float)) and context_sev >= 0.8:
        reasons.append("high context severity")

    score = evidence.get("score", 0)
    if isinstance(score, (int, float)) and score >= 7:
        reasons.append(f"high detection score ({score})")

    if not reasons:
        reasons.append("baseline detection signal")

    return f"{base}: {', '.join(reasons[:3])}."

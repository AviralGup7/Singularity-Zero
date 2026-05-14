"""Human-readable explanation builder for findings."""

from typing import Any


def build_explanation(
    module: str,
    category: str,
    severity: str,
    title: str,
    evidence: dict[str, Any],
    combined_signal: str,
) -> str:
    """Build a human-readable explanation of why this finding was flagged."""
    parts: list[str] = []
    signals = evidence.get("signals", [])

    if category == "idor":
        comparison = evidence.get("comparison") or {}
        if comparison.get("multi_strategy_confirmed"):
            parts.append(
                "Multiple mutation strategies (numeric, UUID, zero, large-value) all returned structurally similar responses, strongly suggesting the endpoint does not enforce object-level access controls."
            )
        elif comparison.get("mutations_confirmed", 0) >= 2:
            parts.append(
                f"At least {comparison['mutations_confirmed']} independent mutations produced consistent response patterns, indicating likely IDOR vulnerability."
            )
        elif comparison:
            parts.append(
                "Response comparison with a mutated identifier returned a structurally similar response, suggesting the endpoint may not validate object ownership."
            )
        else:
            parts.append(
                "The endpoint exposes object identifiers (numeric IDs, UUIDs, or object references) without visible access control enforcement in the URL structure."
            )
        if evidence.get("object_family") and evidence["object_family"] != "generic_object":
            parts.append(
                f"Object family: {evidence['object_family']} — a high-value target for unauthorized data access."
            )

    elif category == "ssrf":
        validation_state = evidence.get("validation_state", "passive_only")
        if validation_state == "active_ready":
            parts.append(
                "This endpoint accepts URL-like or host-like parameters and is suitable for active SSRF validation with controlled callback infrastructure."
            )
        internal_signals = [
            s
            for s in signals
            if "internal_host" in s or "cloud_metadata" in s or "encoded_internal" in s
        ]
        if internal_signals:
            parts.append(
                f"Detected internal/metadata references: {', '.join(internal_signals[:3])}."
            )
        dangerous_signals = [
            s for s in signals if "dangerous_scheme" in s or "protocol_smuggling" in s
        ]
        if dangerous_signals:
            parts.append(f"Dangerous URI schemes detected: {', '.join(dangerous_signals[:3])}.")
        if not parts:
            parts.append(
                "The endpoint accepts parameters that could be used as URL sinks (callback, dest, uri, webhook, etc.), making it a candidate for SSRF testing."
            )

    elif category == "token_leak":
        location = evidence.get("location", "unknown")
        parts.append(f"Token or credential material detected in {location}. ")
        if location == "response_body":
            parts.append(
                "Tokens in response bodies may be cached, logged, or exposed to unauthorized parties."
            )
        elif location == "referer_risk":
            parts.append("Tokens in URLs can leak via HTTP Referer headers to third-party sites.")
        elif location == "header":
            parts.append(
                "Sensitive tokens in headers may be exposed through CORS or proxy misconfigurations."
            )

    elif category == "open_redirect":
        if evidence.get("auth_flow_endpoint"):
            parts.append(
                "This OAuth/signin flow endpoint performs redirects that may be manipulated to redirect users to attacker-controlled sites after authentication."
            )
        else:
            parts.append(
                "The endpoint accepts redirect-like parameters that could be manipulated to redirect users to arbitrary destinations."
            )
        if "cross_host_target" in signals:
            parts.append("Cross-host redirect targets were detected, increasing the severity.")

    elif category == "business_logic":
        if "status_divergence" in signals:
            parts.append(
                "Parameter mutation caused a status code change, indicating the server processes the modified input differently."
            )
        if "content_divergence" in signals:
            parts.append(
                "Response content changed under parameter mutation, suggesting the endpoint's logic is affected by the modified input."
            )
        if module == "parameter_pollution_exploitation":
            parts.append(
                "Duplicate parameter injection changed endpoint behavior — the server may process multiple values for the same parameter inconsistently."
            )
        elif module == "json_mutation_attacks":
            parts.append(
                "JSON-shaped mutations (object/array injection) altered API behavior, suggesting the endpoint may not validate input types strictly."
            )
        elif module == "state_transition_analyzer":
            parts.append(
                "State parameter manipulation allowed skipping workflow steps or accessing stages out of order."
            )
        elif module == "multi_step_flow_breaking_probe":
            parts.append(
                "Direct access to a later workflow step was possible without completing prerequisite steps."
            )

    elif category == "access_control":
        if module == "privilege_escalation_detector":
            parts.append(
                "Endpoint behavior changed after a controlled role/scope parameter modification, suggesting insufficient server-side authorization checks."
            )
        elif module == "cross_user_access_simulation":
            parts.append(
                "The same endpoint returned different responses under different identity contexts, indicating potential cross-user data exposure."
            )
        elif module == "role_based_endpoint_comparison":
            diff_strength = evidence.get("response_diff_strength", "unknown")
            parts.append(
                f"Response differs across roles with {diff_strength} strength — the endpoint may expose role-specific data without proper access controls."
            )
        elif module == "access_boundary_tracker":
            parts.append(
                "Access boundary transitions detected between public, private, and admin views of the same resource family."
            )

    elif category == "authentication_bypass":
        if module == "http_method_override_probe":
            if evidence.get("method_override_detected"):
                parts.append(
                    "Multiple HTTP method override headers (X-HTTP-Method-Override, X-Method-Override) caused response changes, suggesting the server processes method override headers and may allow bypassing method-level access controls."
                )
            else:
                parts.append(
                    "HTTP method override headers produced different response behavior, indicating the server may accept method override directives."
                )
        elif module == "auth_header_tampering_variations":
            if evidence.get("auth_bypass_variant"):
                parts.append(
                    "Removing or altering auth headers returned a successful response, suggesting the endpoint may not enforce authentication consistently."
                )
            else:
                parts.append(
                    "Auth header variations produced different response behaviors, indicating inconsistent authentication enforcement."
                )
        elif module == "unauth_access_check":
            parts.append(
                "The endpoint appears accessible without authentication, returning the same status and JSON structure as authenticated requests."
            )
        elif module == "multi_endpoint_auth_consistency_check":
            parts.append(
                "Authentication enforcement is inconsistent across endpoints on the same host — some protected endpoints may be accessible without proper auth."
            )

    elif category == "broken_authentication":
        if module == "session_reuse_detection":
            parts.append(
                "The same session token was accepted across unrelated flows or privilege boundaries, suggesting insufficient token scoping."
            )
        elif module == "logout_invalidation_check":
            if evidence.get("session_still_valid"):
                parts.append(
                    "Session remained valid after logout — tokens may not be properly invalidated on the server side."
                )
            else:
                parts.append(
                    "Session invalidation behavior detected; verify the invalidation propagates across all related sessions."
                )

    elif category == "xss":
        if module == "stored_xss_signal_detector":
            xss_signals = evidence.get("xss_signals", [])
            parts.append(
                f"Stored XSS signals detected: {', '.join(xss_signals[:3])}. Verify whether the markup is user-controlled and rendered without sanitization."
            )
        elif module == "reflected_xss_probe":
            xss_signals = evidence.get("xss_signals", [])
            parts.append(
                f"Reflected input reached: {', '.join(xss_signals[:3]) if xss_signals else 'response body'}. Confirm whether the reflection reaches an executable context."
            )

    elif category == "exposure":
        if module == "response_structure_validator":
            drift_ratio = evidence.get("drift_ratio", 0)
            sensitive_drift = evidence.get("sensitive_drifting_fields", [])
            if sensitive_drift:
                parts.append(
                    f"JSON response structure drifts across {evidence.get('response_count', 0)} requests with {drift_ratio * 100:.0f}% field inconsistency. Sensitive fields appear conditionally: {', '.join(sensitive_drift[:3])}. This suggests role-based or context-dependent field exposure that may leak data to unauthorized contexts."
                )
            else:
                parts.append(
                    f"JSON response structure drifts across {evidence.get('response_count', 0)} requests with {drift_ratio * 100:.0f}% field inconsistency. Conditional field exposure may indicate access-controlled response shaping or inconsistent API behavior."
                )
        elif module == "sensitive_field_detector":
            parts.append(
                "Sensitive JSON fields (API keys, credentials, PII) are returned in API responses without proper field-level access controls."
            )
        elif module == "error_stack_trace_detector":
            parts.append(
                "Backend stack traces or verbose error messages are exposed, revealing framework, package, and code path details."
            )
        elif module == "environment_file_exposure_checker":
            parts.append(
                "Environment or configuration file may be directly accessible, potentially containing active credentials or internal host references."
            )
        else:
            parts.append(
                f"The endpoint exhibits {title.lower()} characteristics that warrant manual review."
            )

    elif category == "misconfiguration":
        if module == "cors_misconfig_checker":
            if "wildcard_origin_with_credentials" in evidence.get("issues", []):
                parts.append(
                    "Wildcard CORS origin with credentials is a critical misconfiguration allowing any site to make credentialed requests."
                )
            else:
                parts.append(
                    "CORS policy allows broader cross-origin access than typically required."
                )
        elif module == "cache_poisoning_indicator_checker":
            parts.append(
                "Host header reflection in a cacheable response suggests the cache key may not include all relevant headers."
            )
        else:
            parts.append(f"Security header or configuration gap detected: {title.lower()}.")

    elif category == "anomaly":
        if module == "anomaly_detector":
            weighted_score = evidence.get("weighted_score", 0)
            correlated_pairs = evidence.get("correlated_pairs", [])
            if correlated_pairs:
                parts.append(
                    f"Anomalous patterns detected with correlated risk signals ({', '.join(correlated_pairs[:3])}). Weighted exploitability score: {weighted_score:.2f}."
                )
            elif evidence.get("severity") == "high":
                parts.append(
                    f"High-risk anomaly detected (weighted score: {weighted_score:.2f}). Multiple indicators suggest this endpoint warrants immediate manual review."
                )
            else:
                parts.append(
                    f"Anomalous patterns detected (weighted score: {weighted_score:.2f}). Review the flagged signals to confirm whether they represent genuine security concerns."
                )
        elif module == "response_size_anomaly_detector":
            parts.append(
                f"Response size anomaly detected with ratio {evidence.get('anomaly_ratio', 'unknown')}x — may indicate bulk data exposure or over-broad object expansion."
            )
        elif module == "nested_object_traversal":
            parts.append(
                f"Deep nested JSON object graph (traversal score: {evidence.get('traversal_score', 0)}) — may expose related objects or embedded secrets."
            )

    elif category == "redirect":
        if module == "redirect_chain_analyzer":
            parts.append(f"Redirect chain with {evidence.get('redirect_count', 0)} hops detected.")
            if evidence.get("cross_host"):
                parts.append(
                    "Chain crosses host boundaries, which may indicate trust boundary issues."
                )
        elif module == "auth_boundary_redirect_detection":
            if evidence.get("boundary_changed"):
                parts.append(
                    "Redirect crosses authentication boundary — pre-login and post-login destinations differ, which may expose auth flow manipulation opportunities."
                )
            else:
                parts.append("Redirect behavior detected near authentication flows.")

    elif category == "server_side_injection":
        parts.append(
            f"Server-side injection surface detected with vulnerability types: {', '.join(evidence.get('vulnerability_types', [])[:3])}. Focus on the flagged parameter family with controlled probes."
        )

    elif category == "race_condition":
        parts.append(
            "Race-condition sensitive flow detected — concurrent requests may cause inconsistent state changes in booking, checkout, or coupon flows."
        )

    elif category == "payment":
        parts.append(
            f"Payment flow surface at stage '{evidence.get('payment_stage', 'unknown')}' — verify amount, coupon, and ownership controls are server-enforced."
        )

    elif category == "behavioral_deviation":
        if evidence.get("confirmed"):
            parts.append(
                "Confirmed behavioral deviation under controlled single-parameter mutation — the endpoint's logic changes measurably when this parameter is altered."
            )
        else:
            parts.append(
                "Behavioral deviation detected under parameter mutation — replay the variant to confirm reproducibility."
            )

    if combined_signal and not any(s in combined_signal.lower() for s in parts[0].lower() if parts):
        parts.append(f"Combined signals: {combined_signal}.")

    return " ".join(parts) if parts else f"Finding flagged by {module}: {title.lower()}."

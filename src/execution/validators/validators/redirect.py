from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    REDIRECT_PARAM_NAMES,
    build_manual_hint,
    build_validator_result,
    decode_candidate_value,
    endpoint_signature,
    extract_host_candidate,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    is_suspicious_path_redirect,
    normalized_confidence,
    parameter_weight,
    same_host_family,
)
from src.core.models import ValidationResult
from src.execution.validators.validators.shared import (
    REDIRECT_CONFIDENCE_BASE,
    REDIRECT_CONFIDENCE_CAP,
    to_validation_result,
)


def validate_redirect_candidates(
    ranked_priority_urls: list[dict[str, Any]],
    callback_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    callback_host = str((callback_context or {}).get("host", "")).lower()
    callback_ready = (
        str((callback_context or {}).get("validation_state", "passive_only")).lower()
        == "active_ready"
    )
    token_present = bool((callback_context or {}).get("token_present"))
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()

    for item in ranked_priority_urls:
        url = str(item.get("url", "")).strip()
        if not url or is_low_value_endpoint(url):
            continue
        endpoint_key = str(item.get("endpoint_key") or endpoint_signature(url))
        if endpoint_key in seen_patterns:
            continue
        seen_patterns.add(endpoint_key)
        parsed = urlparse(url)
        matched_params: list[str] = []
        signals: set[str] = set()
        weighted_score = int(item.get("score", 0))

        if is_auth_flow_endpoint(url):
            signals.add("auth_flow_endpoint")
            weighted_score += 3

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            normalized_key = key.strip().lower()
            if normalized_key not in REDIRECT_PARAM_NAMES:
                continue
            decoded_value = decode_candidate_value(value)
            if not decoded_value:
                continue
            matched_params.append(normalized_key)
            weighted_score += parameter_weight(normalized_key)
            target_host = extract_host_candidate(decoded_value)
            lowered_value = decoded_value.lower()
            if lowered_value.startswith(("http://", "https://")):
                signals.add("absolute_target")
                if target_host and not same_host_family(target_host, parsed.netloc.lower()):
                    signals.add("cross_host_target")
                if target_host and same_host_family(target_host, parsed.netloc.lower()):
                    signals.add("same_host_redirect")
            elif lowered_value.startswith("//"):
                signals.add("scheme_relative_target")
            elif lowered_value.startswith(("/", "./", "../")):
                signals.add("relative_target")
                if is_suspicious_path_redirect(decoded_value):
                    signals.add("path_only_redirect_target")
            if callback_host and target_host == callback_host:
                signals.add("callback_target_match")
            for nested_name in ("state", "next", "return_to"):
                if nested_name in lowered_value:
                    signals.add("nested_redirect_chain")

            # Detect open redirect bypass techniques
            # 1. Domain prefix bypass (evil.com.target.com)
            if target_host and parsed.netloc.lower().endswith("." + target_host):
                signals.add("domain_prefix_bypass")
            # 2. Domain suffix bypass (target.com.evil.com)
            if target_host and target_host.endswith("." + parsed.netloc.lower()):
                signals.add("domain_suffix_bypass")
            # 3. URL-encoded redirect target
            if "%" in decoded_value and ("http" in decoded_value.lower() or "//" in decoded_value):
                signals.add("encoded_redirect_target")
            # 4. Newline injection in redirect
            if (
                "\n" in decoded_value
                or "\r" in decoded_value
                or "%0a" in lowered_value
                or "%0d" in lowered_value
            ):
                signals.add("newline_injection_redirect")
            # 5. Backslash bypass (common in IIS/ASP.NET)
            if "\\" in decoded_value or "%5c" in lowered_value:
                signals.add("backslash_bypass_redirect")
            # 6. Double URL encoding
            if "%25" in decoded_value:
                signals.add("double_encoded_redirect")
            # 7. Tab character bypass
            if "\t" in decoded_value or "%09" in lowered_value:
                signals.add("tab_bypass_redirect")

        if not matched_params or not signals:
            continue

        # Enhanced bonus scoring for redirect validation
        bonuses = [0.12 if "cross_host_target" in signals else 0.0]
        if "same_host_redirect" in signals:
            bonuses.append(0.08)
        if "auth_flow_endpoint" in signals:
            bonuses.append(0.08)
        if "scheme_relative_target" in signals:
            bonuses.append(0.06)
        if "path_only_redirect_target" in signals:
            bonuses.append(0.07)
        if "nested_redirect_chain" in signals:
            bonuses.append(0.05)
        if "callback_target_match" in signals:
            bonuses.append(0.10)

        validation_state = (
            "active_ready"
            if callback_ready and "callback_target_match" in signals
            else "passive_only"
        )
        if validation_state == "active_ready":
            bonuses.append(0.1)
        if token_present and validation_state == "active_ready":
            bonuses.append(0.05)

        # Additional confidence boost for high-risk combinations
        high_risk_combos = {"cross_host_target", "auth_flow_endpoint", "callback_target_match"}
        if len(signals & high_risk_combos) >= 2:
            bonuses.append(0.08)
        confidence = normalized_confidence(
            base=REDIRECT_CONFIDENCE_BASE,
            score=weighted_score,
            signals=signals,
            bonuses=bonuses,
            cap=REDIRECT_CONFIDENCE_CAP,
        )
        findings.append(
            build_validator_result(
                module="open_redirect_validation",
                category="open_redirect",
                url=url,
                score=weighted_score,
                confidence=confidence,
                signals=sorted(signals),
                validation_state=validation_state,
                hint_message=build_manual_hint("open_redirect", url, {"signals": sorted(signals)}),
                matched_parameters=sorted(set(matched_params)),
                callback_provider=(callback_context or {}).get("provider", "none"),
            )
        )

    findings.sort(key=lambda item: (-item["confidence"], -item["score"], item["url"]))
    return findings[:20]


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    callback_context = context.get("callback_context") if isinstance(context, dict) else None
    items = validate_redirect_candidates([target], callback_context)
    if not items:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "failed"},
            validator="redirect",
            category="open_redirect",
        )
    return to_validation_result(items[0], validator="redirect", category="open_redirect")
